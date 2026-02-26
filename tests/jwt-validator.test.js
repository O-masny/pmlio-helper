/**
 * Tests for JWT Challenge Validator
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// 1. Generate RS256 keypair for testing FIRST
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// 2. Inject keys into the environment BEFORE requiring the module
process.env.PMLIO_JWT_PUBLIC_KEY = publicKey;
process.env.PMLIO_JWT_PRIVATE_KEY = privateKey;
process.env.NODE_ENV = 'test';

// 3. Now require the validator so it picks up the real generated PEM string
const { validateChallengeJwt, resetJtiStore, createTestJwt } = require('../src/jwt-validator');

const TEST_HASH = 'a'.repeat(64); // Mock SHA-256

beforeEach(() => {
    resetJtiStore();
});

describe('JWT Validator', () => {
    test('accepts valid challenge JWT', () => {
        const token = createTestJwt(TEST_HASH);
        const payload = validateChallengeJwt(token);

        expect(payload.hash).toBe(TEST_HASH);
        expect(payload.aud).toBe('pmlio-signing');
        expect(payload.jti).toBeDefined();
    });

    test('rejects expired JWT', () => {
        const token = createTestJwt(TEST_HASH, { expiresIn: '-10s' });

        expect(() => validateChallengeJwt(token)).toThrow(/expired/i);
    });

    test('rejects wrong audience', () => {
        const token = jwt.sign(
            { hash: TEST_HASH, jti: 'test-jti-wrong-aud' },
            privateKey,
            { algorithm: 'RS256', audience: 'wrong-audience', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/audience/i);
    });

    test('rejects replay (same JTI used twice)', () => {
        const fixedJti = 'replay-test-jti-123';
        const token1 = createTestJwt(TEST_HASH, { jti: fixedJti });
        const token2 = createTestJwt(TEST_HASH, { jti: fixedJti });

        // First use should succeed
        validateChallengeJwt(token1);

        // Second use of same JTI should fail
        expect(() => validateChallengeJwt(token2)).toThrow(/replay/i);
    });

    test('rejects JWT without hash', () => {
        const token = jwt.sign(
            { jti: 'no-hash-jti' },
            privateKey,
            { algorithm: 'RS256', audience: 'pmlio-signing', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/hash/i);
    });

    test('rejects JWT without JTI', () => {
        const token = jwt.sign(
            { hash: TEST_HASH },
            privateKey,
            { algorithm: 'RS256', audience: 'pmlio-signing', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/jti/i);
    });

    test('rejects tampered JWT (wrong secret)', () => {
        const tamperedKey = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        }).privateKey;

        const token = jwt.sign(
            { hash: TEST_HASH, jti: 'tampered-jti' },
            tamperedKey,
            { algorithm: 'RS256', audience: 'pmlio-signing', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/signature/i);
    });
});
