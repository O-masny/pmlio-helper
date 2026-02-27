/**
 * Localhost HTTP Server (Express)
 *
 * Listens on 127.0.0.1:14725 (plain HTTP — localhost is a W3C "trustworthy origin").
 * Provides /health, /certificates, and /sign endpoints.
 */
const express = require('express');
const http = require('http');
const cors = require('cors');
const { validateChallengeJwt } = require('./jwt-validator');
const pkcs11 = require('./pkcs11'); // Require the whole module to access signHashes easily
const { listCertificates, signHash, getReaderStatus } = pkcs11;

const PORT = 14725;
const HOST = '127.0.0.1';

let server = null;

/**
 * CORS whitelist: only PMLio domains and localhost
 */
const ALLOWED_ORIGINS = [
    /^https?:\/\/.*\.pmlio\.cz$/,
    /^https?:\/\/localhost(:\d+)?$/,
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
];

function createApp() {
    const app = express();

    app.use(express.json({ limit: '1mb' }));
    app.use(cors({
        origin: (origin, callback) => {
            // Allow requests with no origin (e.g., curl, Electron)
            if (!origin) return callback(null, true);
            const allowed = ALLOWED_ORIGINS.some(pattern => pattern.test(origin));
            if (allowed) return callback(null, true);
            return callback(new Error(`CORS: Origin ${origin} not allowed`));
        },
        credentials: true,
    }));

    // ============================================================
    // GET /health — Status check
    // ============================================================
    app.get('/health', (req, res) => {
        const status = getReaderStatus();
        res.json({
            status: 'ok',
            version: require('../package.json').version,
            reader_connected: status.readerConnected,
            token_present: status.tokenPresent,
            reader_name: status.readerName || null,
        });
    });

    // ============================================================
    // GET /certificates — List signing certificates on HW token
    // ============================================================
    app.get('/certificates', async (req, res) => {
        try {
            const certs = await listCertificates();
            res.json(certs);
        } catch (err) {
            console.error('[Server] Failed to list certificates:', err);
            res.status(500).json({
                error: 'Failed to enumerate certificates',
                detail: err.message,
                code: err.code || 'UNKNOWN'
            });
        }
    });

    // ============================================================
    // POST /sign — Sign a record hash
    // ============================================================
    app.post('/sign', async (req, res) => {
        const { challenge_jwt, certificate_id } = req.body;

        if (!challenge_jwt || !certificate_id) {
            return res.status(400).json({ error: 'Missing challenge_jwt or certificate_id' });
        }

        // 1. Validate JWT
        let payload;
        try {
            payload = validateChallengeJwt(challenge_jwt);
        } catch (err) {
            console.error('[Server] JWT validation failed:', err.message);
            return res.status(401).json({ error: 'Invalid challenge', detail: err.message });
        }

        // 2. Sign the hash using PKCS#11
        try {
            const result = await signHash(payload.hash, certificate_id);
            res.json({
                signature_value: result.signatureValue,
                algorithm: result.algorithm,
                cert_chain_pem: result.certChainPem,
                signed_hash: payload.hash,
                session_id: payload.jti,
            });
        } catch (err) {
            console.error('[Server] Signing failed:', err);
            res.status(500).json({
                error: 'Signing failed',
                detail: err.message,
                code: err.code || 'UNKNOWN'
            });
        }
    });

    // ============================================================
    // POST /sign-many — Sign multiple record hashes (Batch)
    // ============================================================
    app.post('/sign-many', async (req, res) => {
        const { batch_session_id, challenge_jwt, certificate_id, items } = req.body;

        if (!challenge_jwt || !certificate_id || !batch_session_id || !Array.isArray(items)) {
            return res.status(400).json({ error: 'Missing challenge_jwt, certificate_id, batch_session_id or items array' });
        }

        // 1. Validate JWT (must contain the correct batch session ID and array of hashes)
        let payload;
        try {
            payload = validateChallengeJwt(challenge_jwt);
        } catch (err) {
            console.error('[Server] Batch JWT validation failed:', err.message);
            return res.status(401).json({ error: 'Invalid challenge', detail: err.message });
        }

        if (payload.jti !== batch_session_id) {
            return res.status(401).json({ error: 'Session ID mismatch in JWT' });
        }

        const requestedHashes = items.map(item => item.record_hash_b64 || item.hash);

        // Verify that the requested hashes match the allowed hashes in the JWT claim
        if (!payload.hashes) {
            return res.status(401).json({ error: 'JWT does not contain a hashes array for batch signing' });
        }

        for (const h of requestedHashes) {
            if (!payload.hashes.includes(h)) {
                return res.status(401).json({ error: `Hash ${h} is not authorized by this challenge JWT` });
            }
        }

        // 2. Sign all hashes iteratively using PKCS#11
        try {
            const results = await pkcs11.signHashes(requestedHashes, certificate_id);

            // Map results back to the original items
            const mappedResults = items.map((item, index) => {
                // Ensure order matches requestedHashes
                const r = results[index];
                return {
                    record_id: item.record_id,
                    status: r.status,
                    signature_b64: r.signatureValue,
                    error_code: r.error
                };
            });

            // The Cert Chain is extracted from the first successful result
            const successfulResult = results.find(r => r.status === 'OK');

            res.json({
                signing_cert_pem: successfulResult ? successfulResult.certChainPem : null,
                cert_chain_pem: successfulResult ? successfulResult.certChainPem : null,
                signed_at_utc: new Date().toISOString(),
                results: mappedResults,
            });
        } catch (err) {
            console.error('[Server] Batch signing failed:', err);
            res.status(500).json({
                error: 'Batch signing failed',
                detail: err.message,
                code: err.code || 'UNKNOWN'
            });
        }
    });

    // Global error handler
    app.use((err, req, res, next) => {
        console.error('[Server] Unhandled error:', err);
        res.status(500).json({ error: 'Internal server error' });
    });

    return app;
}

async function startServer() {
    const app = createApp();

    return new Promise((resolve, reject) => {
        server = http.createServer(app);
        server.listen(PORT, HOST, () => {
            console.log(`[Server] Listening on http://${HOST}:${PORT}`);
            resolve(server);
        });
        server.on('error', reject);
    });
}

function stopServer() {
    if (server) {
        server.close();
        server = null;
    }
}

module.exports = { createApp, startServer, stopServer };
