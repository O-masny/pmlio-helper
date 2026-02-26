/**
 * Tests for JWT Challenge Validator
 */
const { validateChallengeJwt, resetJtiStore, createTestJwt } = require('../src/jwt-validator');
const jwt = require('jsonwebtoken');

const TEST_SECRET = 'pmlio-helper-dev-secret-change-in-production';
const TEST_HASH = 'a'.repeat(64); // Mock SHA-256

beforeEach(() => {
    resetJtiStore();
});

describe('JWT Validator', () => {
    test('accepts valid challenge JWT', () => {
        const token = createTestJwt(TEST_HASH);
        const payload = validateChallengeJwt(token);

        expect(payload.hash).toBe(TEST_HASH);
        expect(payload.aud).toBe('pmlio-helper');
        expect(payload.jti).toBeDefined();
    });

    test('rejects expired JWT', () => {
        const token = createTestJwt(TEST_HASH, { expiresIn: '-10s' });

        expect(() => validateChallengeJwt(token)).toThrow(/expired/i);
    });

    test('rejects wrong audience', () => {
        const token = jwt.sign(
            { hash: TEST_HASH, jti: 'test-jti-wrong-aud' },
            TEST_SECRET,
            { audience: 'wrong-audience', expiresIn: '120s' }
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
            TEST_SECRET,
            { audience: 'pmlio-helper', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/hash/i);
    });

    test('rejects JWT without JTI', () => {
        const token = jwt.sign(
            { hash: TEST_HASH },
            TEST_SECRET,
            { audience: 'pmlio-helper', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/jti/i);
    });

    test('rejects tampered JWT (wrong secret)', () => {
        const token = jwt.sign(
            { hash: TEST_HASH, jti: 'tampered-jti' },
            'wrong-secret',
            { audience: 'pmlio-helper', expiresIn: '120s' }
        );

        expect(() => validateChallengeJwt(token)).toThrow(/signature/i);
    });
});
