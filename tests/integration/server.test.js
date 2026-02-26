/**
 * Integration Tests — Server API Endpoints
 *
 * Tests the full Express server with mock PKCS#11.
 * Runs WITHOUT Electron (pure Node.js).
 */

// Force test/mock mode
process.env.NODE_ENV = 'test';
process.env.PMLIO_MOCK_PKCS11 = 'true';

// Pre-generate certs before mocking (avoids Jest module resolution issues)
const crypto = require('crypto');
const { generateKeyPairSync, createSign, createCertificate } = crypto;

function generateSelfSignedCert() {
    // Use Node's built-in crypto for a self-signed cert
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // For supertest we just need valid PEM key/cert strings
    // We'll create a minimal self-signed cert using node-forge
    // But require it HERE (before jest.mock) to avoid resolution issues
    const forge = require('node-forge');
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
    const attrs = [{ name: 'commonName', value: 'localhost' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    return {
        key: forge.pki.privateKeyToPem(keys.privateKey),
        cert: forge.pki.certificateToPem(cert),
    };
}

const testCerts = generateSelfSignedCert();

// Mock cert-store AFTER generating certs
// Mock cert-store with static dummy certs
jest.mock('../../src/cert-store', () => ({
    ensureCerts: () => ({
        key: 'MOCK_PRIVATE_KEY',
        cert: 'MOCK_CERTIFICATE',
    }),
}));

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
