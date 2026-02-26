/**
 * Self-Signed Certificate Store
 *
 * Generates and caches a self-signed TLS certificate
 * for the localhost HTTPS server.
 */
const fs = require('fs');
const path = require('path');
const selfsigned = require('selfsigned');
const { app } = require('electron');

const CERT_DIR = process.env.NODE_ENV === 'test'
    ? path.join(__dirname, '..', '.test-certs')
    : path.join(app?.getPath('userData') || path.join(__dirname, '..'), 'certs');

const KEY_PATH = path.join(CERT_DIR, 'server.key');
const CERT_PATH = path.join(CERT_DIR, 'server.crt');

/**
 * Ensure self-signed certificates exist for localhost.
 * Generates new ones if missing.
 *
 * @returns {{ key: string, cert: string }}
 */
function ensureCerts() {
    // Return existing certs if available
    if (fs.existsSync(KEY_PATH) && fs.existsSync(CERT_PATH)) {
        return {
            key: fs.readFileSync(KEY_PATH, 'utf8'),
            cert: fs.readFileSync(CERT_PATH, 'utf8'),
        };
    }

    console.log('[CertStore] Generating self-signed certificate for localhost...');

    // Create cert directory
    fs.mkdirSync(CERT_DIR, { recursive: true });

    // Generate self-signed cert valid for 5 years
    const attrs = [
        { name: 'commonName', value: 'PMLio Helper (localhost)' },
        { name: 'organizationName', value: 'PMLio s.r.o.' },
        { name: 'countryName', value: 'CZ' },
    ];

    const pems = selfsigned.generate(attrs, {
        keySize: 2048,
        days: 1825, // 5 years
        algorithm: 'sha256',
        extensions: [
            {
                name: 'subjectAltName',
                altNames: [
                    { type: 2, value: 'localhost' },       // DNS
                    { type: 7, ip: '127.0.0.1' },          // IP
                ],
            },
        ],
    });

    fs.writeFileSync(KEY_PATH, pems.private, 'utf8');
    fs.writeFileSync(CERT_PATH, pems.cert, 'utf8');

    console.log('[CertStore] Certificate generated successfully.');

    return {
        key: pems.private,
        cert: pems.cert,
    };
}

module.exports = { ensureCerts };
