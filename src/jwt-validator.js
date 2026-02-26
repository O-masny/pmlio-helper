/**
 * JWT Challenge Validator
 *
 * Validates challenge JWTs issued by PMLio backend.
 * Enforces audience, expiration, and replay protection.
 */
const jwt = require('jsonwebtoken');

/**
 * In-memory set of used JTIs for replay protection.
 * JTIs are kept for 5 minutes then purged.
 */
const usedJtis = new Map(); // jti -> timestamp
const JTI_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Public key from PMLio backend for verifying challenge JWTs using RS256.
 * In a production environment, this should be securely deployed alongside the helper.
 */
const JWT_PUBLIC_KEY = process.env.PMLIO_JWT_PUBLIC_KEY;

if (!JWT_PUBLIC_KEY) {
    console.error('CRITICAL: Missing PMLIO_JWT_PUBLIC_KEY environment variable. Challenge JWT cannot be validated.');
    process.exit(1);
}

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

    // 2. Verify JWT signature + claims using RS256 OpenSSL Public Key
    const payload = jwt.verify(token, JWT_PUBLIC_KEY, {
        algorithms: ['RS256'], // Strictly enforce asymmetric cryptography
        audience: JWT_AUDIENCE,
        clockTolerance: 5, // 5 second clock skew tolerance
    });

    // 3. Require hash
    if (!payload.hash || typeof payload.hash !== 'string') {
        throw new Error('JWT missing required "hash" claim');
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
