/**
 * Localhost HTTPS Server (Express)
 *
 * Listens on 127.0.0.1:14725 with a self-signed certificate.
 * Provides /health, /certificates, and /sign endpoints.
 */
const express = require('express');
const https = require('https');
const cors = require('cors');
const { ensureCerts } = require('./cert-store');
const { validateChallengeJwt } = require('./jwt-validator');
const { listCertificates, signHash, getReaderStatus } = require('./pkcs11');

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
            console.error('[Server] Failed to list certificates:', err.message);
            res.status(500).json({ error: 'Failed to enumerate certificates', detail: err.message });
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
            console.error('[Server] Signing failed:', err.message);
            res.status(500).json({ error: 'Signing failed', detail: err.message });
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
    const { key, cert } = ensureCerts();

    return new Promise((resolve, reject) => {
        server = https.createServer({ key, cert }, app);
        server.listen(PORT, HOST, () => {
            console.log(`[Server] Listening on https://${HOST}:${PORT}`);
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
