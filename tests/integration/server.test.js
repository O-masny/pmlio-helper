/**
 * Integration Tests — Server API Endpoints
 *
 * Tests the full Express server (plain HTTP) with mock PKCS#11.
 * Runs WITHOUT Electron (pure Node.js).
 */

// Force test/mock mode
process.env.NODE_ENV = 'test';
process.env.PMLIO_MOCK_PKCS11 = 'true';

// Generate RSA key pair for JWT signing/verification in tests
const crypto = require('crypto');
const { generateKeyPairSync } = crypto;

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

process.env.PMLIO_JWT_PUBLIC_KEY = publicKey;
process.env.PMLIO_JWT_PRIVATE_KEY = privateKey;

const { createApp } = require('../../src/server');
const { createTestJwt, resetJtiStore } = require('../../src/jwt-validator');
const { initPkcs11 } = require('../../src/pkcs11');
const request = require('supertest');

let app;

beforeAll(async () => {
    await initPkcs11();
    app = createApp();
});

beforeEach(() => {
    resetJtiStore();
});

describe('GET /health', () => {
    test('returns status ok with reader info', async () => {
        const res = await request(app).get('/health');

        expect(res.status).toBe(200);
        expect(res.body.status).toBe('ok');
        expect(res.body.version).toBeDefined();
        expect(res.body.reader_connected).toBe(true);
        expect(res.body.token_present).toBe(true);
    });
});

describe('GET /certificates', () => {
    test('returns mock certificates', async () => {
        const res = await request(app).get('/certificates');

        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body.length).toBeGreaterThan(0);
        expect(res.body[0]).toHaveProperty('id');
        expect(res.body[0]).toHaveProperty('subject_cn');
        expect(res.body[0]).toHaveProperty('issuer_cn');
        expect(res.body[0]).toHaveProperty('is_qualified');
    });
});

describe('POST /sign', () => {
    const TEST_HASH = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';

    test('signs hash with valid JWT', async () => {
        const token = createTestJwt(TEST_HASH);

        const res = await request(app)
            .post('/sign')
            .send({ challenge_jwt: token, certificate_id: 'mock-cert-001' });

        expect(res.status).toBe(200);
        expect(res.body.signature_value).toBeDefined();
        expect(res.body.algorithm).toBe('SHA256withRSA');
        expect(res.body.cert_chain_pem).toContain('BEGIN CERTIFICATE');
        expect(res.body.signed_hash).toBe(TEST_HASH);
    });

    test('rejects request without JWT', async () => {
        const res = await request(app)
            .post('/sign')
            .send({ certificate_id: 'mock-cert-001' });

        expect(res.status).toBe(400);
        expect(res.body.error).toContain('Missing');
    });

    test('rejects expired JWT', async () => {
        const token = createTestJwt(TEST_HASH, { expiresIn: '-10s' });

        const res = await request(app)
            .post('/sign')
            .send({ challenge_jwt: token, certificate_id: 'mock-cert-001' });

        expect(res.status).toBe(401);
    });

    test('rejects replay attack', async () => {
        const fixedJti = 'replay-integration-test';
        const token1 = createTestJwt(TEST_HASH, { jti: fixedJti });
        const token2 = createTestJwt(TEST_HASH, { jti: fixedJti });

        // First request succeeds
        const res1 = await request(app)
            .post('/sign')
            .send({ challenge_jwt: token1, certificate_id: 'mock-cert-001' });
        expect(res1.status).toBe(200);

        // Same JTI = replay = rejected
        const res2 = await request(app)
            .post('/sign')
            .send({ challenge_jwt: token2, certificate_id: 'mock-cert-001' });
        expect(res2.status).toBe(401);
        expect(res2.body.detail).toContain('replay');
    });
});

describe('POST /sign-many', () => {
    const BATCH_SESSION_ID = 'batch-uuid-999';
    const TEST_HASH_1 = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
    const TEST_HASH_2 = 'abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    test('signs multiple hashes with valid batch JWT', async () => {
        const jwt = require('jsonwebtoken');
        const token = jwt.sign(
            {
                hashes: [TEST_HASH_1, TEST_HASH_2],
                jti: BATCH_SESSION_ID,
                tenant_domain: 'test.pmlio.cz'
            },
            privateKey,
            {
                algorithm: 'RS256',
                audience: 'pmlio-signing',
                expiresIn: '120s'
            }
        );

        const res = await request(app)
            .post('/sign-many')
            .send({
                challenge_jwt: token,
                certificate_id: 'mock-cert-001',
                batch_session_id: BATCH_SESSION_ID,
                items: [
                    { record_id: 'r1', hash: TEST_HASH_1 },
                    { record_id: 'r2', hash: TEST_HASH_2 }
                ]
            });

        expect(res.status).toBe(200);
        expect(res.body.cert_chain_pem).toContain('BEGIN CERTIFICATE');
        expect(res.body.results.length).toBe(2);

        expect(res.body.results[0].status).toBe('OK');
        expect(res.body.results[0].record_id).toBe('r1');
        expect(res.body.results[0].signature_b64).toBeDefined();

        expect(res.body.results[1].status).toBe('OK');
        expect(res.body.results[1].record_id).toBe('r2');
        expect(res.body.results[1].signature_b64).toBeDefined();
    });

    test('rejects hash not listed in JWT hashes array', async () => {
        const jwt = require('jsonwebtoken');
        const token = jwt.sign(
            {
                hashes: [TEST_HASH_1], // Test hash 2 is missing
                jti: BATCH_SESSION_ID,
                tenant_domain: 'test.pmlio.cz'
            },
            privateKey,
            {
                algorithm: 'RS256',
                audience: 'pmlio-signing',
                expiresIn: '120s'
            }
        );

        const res = await request(app)
            .post('/sign-many')
            .send({
                challenge_jwt: token,
                certificate_id: 'mock-cert-001',
                batch_session_id: BATCH_SESSION_ID,
                items: [
                    { record_id: 'r1', hash: TEST_HASH_1 },
                    { record_id: 'r2', hash: TEST_HASH_2 } // Unauthorized
                ]
            });

        expect(res.status).toBe(401);
        expect(res.body.error).toContain('not authorized');
    });
});
