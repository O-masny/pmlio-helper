/**
 * JWT Challenge Validator
 *
 * Validates challenge JWTs issued by PMLio backend.
 * Enforces audience, expiration, and replay protection.
 */
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

/**
 * In-memory set of used JTIs for replay protection.
 * JTIs are kept for 5 minutes then purged.
 */
const usedJtis = new Map(); // jti -> timestamp
const JTI_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Load the RS256 public key for JWT verification.
 *
 * Priority:
 *  1. Bundled file: resources/jwt-public.pem (shipped inside .exe / .dmg)
 *  2. Environment variable: PMLIO_JWT_PUBLIC_KEY (for dev / CI)
 *  3. Test mode: uses test-injected key from PMLIO_JWT_PUBLIC_KEY env
 */
function loadPublicKey() {
    // In test mode, use whatever is injected (may be a PEM cert for supertest)
    if (process.env.NODE_ENV === 'test') {
        return process.env.PMLIO_JWT_PUBLIC_KEY || 'MOCK_PUBLIC_KEY';
    }

    // Try bundled file first (works in Electron packaged app)
    const bundledPaths = [
        // Electron packaged app: resources are next to app.asar
        path.join(process.resourcesPath || '', 'jwt-public.pem'),
        // Development: relative to project root
        path.join(__dirname, '..', 'resources', 'jwt-public.pem'),
    ];

    for (const p of bundledPaths) {
        try {
            if (fs.existsSync(p)) {
                const key = fs.readFileSync(p, 'utf8');
                console.log(`[JWT] Loaded public key from: ${p}`);
                return key;
            }
        } catch (_) { /* try next */ }
    }

    // Fallback: environment variable (for docker / CI / dev)
    if (process.env.PMLIO_JWT_PUBLIC_KEY) {
        console.log('[JWT] Loaded public key from PMLIO_JWT_PUBLIC_KEY env var');
        return process.env.PMLIO_JWT_PUBLIC_KEY;
    }

    console.error('CRITICAL: No JWT public key found. Place jwt-public.pem in resources/ or set PMLIO_JWT_PUBLIC_KEY.');
    process.exit(1);
}

const PUBLIC_KEY_TO_USE = loadPublicKey();

const JWT_AUDIENCE = 'pmlio-signing'; // Matches the audience set by the PHP backend

/**
 * Validate a challenge JWT from the PMLio backend.
 *
 * @param {string} token - The JWT string
 * @returns {object} Decoded payload with { hash, jti, tenant_domain, ... }
 * @throws {Error} If validation fails
 */
function validateChallengeJwt(token) {
    // 1. Purge expired JTIs
    purgeExpiredJtis();

    let payload;

    if (process.env.PMLIO_MOCK_PKCS11 === 'true') {
        // In MOCK mode (especially against remote VPS backends), the local helper
        // doesn't have the correct RSA public key. Bypass crypto verification.
        payload = jwt.decode(token);
        if (!payload) throw new Error('JWT could not be decoded in mock mode');
    } else {
        // 2. Verify JWT signature + claims using RS256 OpenSSL Public Key
        payload = jwt.verify(token, PUBLIC_KEY_TO_USE, {
            algorithms: ['RS256'], // Strictly enforce asymmetric cryptography
            audience: JWT_AUDIENCE,
            clockTolerance: 5, // 5 second clock skew tolerance
        });
    }

    // 3. Require hash or hashes (for batch)
    if (!payload.hash && !payload.hashes) {
        throw new Error('JWT missing required "hash" or "hashes" claim');
    }
    if (payload.hashes && !Array.isArray(payload.hashes)) {
        throw new Error('JWT "hashes" claim must be an array');
    }

    // 4. Require JTI (unique identifier)
    if (!payload.jti) {
        throw new Error('JWT missing required "jti" claim');
    }

    // 5. Replay protection
    if (usedJtis.has(payload.jti)) {
        throw new Error(`JWT replay detected: jti "${payload.jti}" already used`);
    }
    usedJtis.set(payload.jti, Date.now());

    return payload;
}

/**
 * Remove JTIs older than TTL.
 */
function purgeExpiredJtis() {
    const cutoff = Date.now() - JTI_TTL_MS;
    for (const [jti, timestamp] of usedJtis.entries()) {
        if (timestamp < cutoff) {
            usedJtis.delete(jti);
        }
    }
}

/**
 * Reset JTI store (for testing).
 */
function resetJtiStore() {
    usedJtis.clear();
}

/**
 * Create a test JWT (for development/testing only).
 * WARNING: Since we moved to RS256, creating a test JWT locally requires a PRIVATE key.
 * If you do not have a PMLIO_JWT_PRIVATE_KEY injected, this will fall back to using
 * a mocked HS256 algorithm just for local test endpoints, but production expects RS256.
 */
function createTestJwt(hash, options = {}) {
    const { v4: uuidv4 } = require('uuid');
    const privateKey = process.env.PMLIO_JWT_PRIVATE_KEY || 'secret';
    const alg = process.env.PMLIO_JWT_PRIVATE_KEY ? 'RS256' : 'HS256';

    return jwt.sign(
        {
            hash,
            tenant_domain: options.tenantDomain || 'test.pmlio.cz',
            jti: options.jti || uuidv4(),
        },
        privateKey,
        {
            algorithm: alg,
            audience: JWT_AUDIENCE,
            expiresIn: options.expiresIn || '120s',
            issuer: 'pmlio-backend',
        }
    );
}

module.exports = { validateChallengeJwt, resetJtiStore, createTestJwt };
