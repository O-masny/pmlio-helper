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
 * Public key(s) from PMLio backend for verifying challenge JWTs.
 * In production, this would be fetched from a JWKS endpoint.
 *
 * For development/testing, we use a shared HMAC secret.
 */
const JWT_SECRET = process.env.PMLIO_JWT_SECRET || 'pmlio-helper-dev-secret-change-in-production';
const JWT_AUDIENCE = 'pmlio-helper';

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

    // 2. Verify JWT signature + claims
    const payload = jwt.verify(token, JWT_SECRET, {
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
 */
function createTestJwt(hash, options = {}) {
    const { v4: uuidv4 } = require('uuid');
    return jwt.sign(
        {
            hash,
            tenant_domain: options.tenantDomain || 'test.pmlio.cz',
            jti: options.jti || uuidv4(),
        },
        JWT_SECRET,
        {
            audience: JWT_AUDIENCE,
            expiresIn: options.expiresIn || '120s',
            issuer: 'pmlio-backend',
        }
    );
}

module.exports = { validateChallengeJwt, resetJtiStore, createTestJwt };
