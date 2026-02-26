/**
 * PKCS#11 Wrapper — USB Token Interface
 *
 * Provides certificate enumeration and hash signing
 * via PKCS#11 interface (SafeNet, Bit4Id, etc.).
 *
 * In development/test mode, uses a software mock.
 */

let pkcs11Module = null;
let isInitialized = false;
let readerStatus = {
    readerConnected: false,
    tokenPresent: false,
    readerName: null,
};

// Global pkcs11js reference – optional dependency handling
let pkcs11js;
try {
    pkcs11js = require('pkcs11js');
} catch (e) {
    console.warn('[PKCS#11] pkcs11js module not available, mock mode only');
    pkcs11js = null;
}

/**
 * Convert DER buffer to PEM string
 * @param {Buffer} der
 * @returns {string}
 */
function derToPem(der) {
    const base64 = der.toString('base64');
    const lines = base64.match(/.{1,64}/g) || [];
    return ['-----BEGIN CERTIFICATE-----', ...lines, '-----END CERTIFICATE-----'].join('\n');
}

/**
 * Known PKCS#11 library paths per platform.
 */
const PKCS11_LIBS = {
    win32: [
        'C:\\Windows\\System32\\eTPKCS11.dll',          // SafeNet eToken
        'C:\\Windows\\System32\\bit4ipki.dll',           // Bit4Id
        'C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
    ],
    darwin: [
        '/usr/local/lib/opensc-pkcs11.so',
        '/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib',
    ],
    linux: [
        '/usr/lib/opensc-pkcs11.so',
        '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
    ],
};

/**
 * Initialize PKCS#11 module — detect reader and token.
 */
async function initPkcs11() {
    // In test/dev mode without real hardware, use mock
    if (process.env.PMLIO_MOCK_PKCS11 === 'true' || process.env.NODE_ENV === 'test') {
        console.log('[PKCS#11] Running in MOCK mode');
        readerStatus = {
            readerConnected: true,
            tokenPresent: true,
            readerName: 'Mock SmartCard Reader',
        };
        isInitialized = true;
        return true;
    }

    try {
        const pkcs11js = require('pkcs11js');
        pkcs11Module = new pkcs11js.PKCS11();

        const libs = PKCS11_LIBS[process.platform] || [];
        for (const lib of libs) {
            try {
                pkcs11Module.load(lib);
                pkcs11Module.C_Initialize();

                // Check for slots (readers)
                const slots = pkcs11Module.C_GetSlotList(false);
                if (slots.length > 0) {
                    const slotInfo = pkcs11Module.C_GetSlotInfo(slots[0]);
                    const tokenInfo = pkcs11Module.C_GetTokenInfo(slots[0]);

                    readerStatus = {
                        readerConnected: true,
                        tokenPresent: (slotInfo.flags & 0x02) !== 0, // CKF_TOKEN_PRESENT
                        readerName: slotInfo.slotDescription?.trim() || 'Unknown Reader',
                    };

                    console.log(`[PKCS#11] Loaded: ${lib}`);
                    console.log(`[PKCS#11] Reader: ${readerStatus.readerName}`);
                    isInitialized = true;
                    return true;
                }
            } catch (e) {
                // Try next library
                continue;
            }
        }

        console.warn('[PKCS#11] No PKCS#11 library or reader found');
        return false;
    } catch (err) {
        console.error('[PKCS#11] Init failed:', err.message);
        return false;
    }
}

/**
 * Get current reader status.
 */
function getReaderStatus() {
    return { ...readerStatus };
}

/**
 * List certificates available on the token.
 * Returns array of cert info objects.
 */
async function listCertificates() {
    if (process.env.PMLIO_MOCK_PKCS11 === 'true' || process.env.NODE_ENV === 'test') {
        return getMockCertificates();
    }

    if (!isInitialized || !pkcs11Module) {
        throw new Error('PKCS#11 not initialized');
    }

    // Enumerate certificates (CKO_CERTIFICATE) on the token
    const slot = pkcs11Module.C_GetSlotList(true)[0];
    const session = pkcs11Module.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION);
    try {
        // Find all certificate objects
        pkcs11Module.C_FindObjectsInit(session, [{ type: pkcs11js.CKO_CERTIFICATE }]);
        const handles = pkcs11Module.C_FindObjects(session, 100);
        pkcs11Module.C_FindObjectsFinal(session);
        const certs = handles.map(handle => {
            const attrs = pkcs11Module.C_GetAttributeValue(session, handle, [
                { type: pkcs11js.CKA_ID },
                { type: pkcs11js.CKA_SUBJECT },
                { type: pkcs11js.CKA_ISSUER },
                { type: pkcs11js.CKA_VALUE },
                { type: pkcs11js.CKA_LABEL },
                { type: pkcs11js.CKA_CERTIFICATE_TYPE },
                { type: pkcs11js.CKA_TRUSTED },
            ]);
            const id = attrs[0].value.toString('hex');
            const subject = attrs[1].value.toString('utf8');
            const issuer = attrs[2].value.toString('utf8');
            const der = attrs[3].value; // DER encoded cert
            const pem = derToPem(der);
            const label = attrs[4].value.toString('utf8');
            const certType = attrs[5].value.readUInt32LE(0);
            const trusted = !!attrs[6].value.readUInt8(0);
            // Simple validity extraction (not full X.509 parsing)
            return {
                id,
                label,
                subject_cn: subject,
                issuer_cn: issuer,
                is_qualified: trusted,
                certPem: pem,
            };
        });
        return certs;
    } finally {
        pkcs11Module.C_CloseSession(session);
    }
}

/**
 * Sign a SHA-256 hash using the specified certificate's private key.
 *
 * @param {string} hash - Hex-encoded SHA-256 hash
 * @param {string} certificateId - ID of the certificate to use
 * @returns {object} { signatureValue, algorithm, certChainPem }
 */
async function signHash(hash, certificateId) {
    if (process.env.PMLIO_MOCK_PKCS11 === 'true' || process.env.NODE_ENV === 'test') {
        return getMockSignature(hash, certificateId);
    }

    if (!isInitialized || !pkcs11Module) {
        throw new Error('PKCS#11 not initialized');
    }

    const slot = pkcs11Module.C_GetSlotList(true)[0];
    const session = pkcs11Module.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    try {
        // Login — SafeNet tokens support protected authentication path,
        // which triggers the native PIN dialog automatically.
        // Fallback to env var PIN for headless / CI environments.
        const tokenInfo = pkcs11Module.C_GetTokenInfo(slot);
        const hasProtectedAuth = (tokenInfo.flags & 0x100) !== 0; // CKF_PROTECTED_AUTHENTICATION_PATH
        if (hasProtectedAuth) {
            pkcs11Module.C_Login(session, pkcs11js.CKU_USER, null);
        } else {
            const pin = process.env.PMLIO_PKCS11_PIN || '';
            pkcs11Module.C_Login(session, pkcs11js.CKU_USER, pin);
        }
        // Find private key by CKA_ID matching the certificateId (hex string)
        const idBuffer = Buffer.from(certificateId, 'hex');
        pkcs11Module.C_FindObjectsInit(session, [{ type: pkcs11js.CKO_PRIVATE_KEY, value: idBuffer }]);
        const keyHandles = pkcs11Module.C_FindObjects(session, 1);
        pkcs11Module.C_FindObjectsFinal(session);
        if (keyHandles.length === 0) {
            throw new Error('Private key not found for certificate ID');
        }
        const keyHandle = keyHandles[0];
        // Prepare mechanism
        const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
        pkcs11Module.C_SignInit(session, mechanism, keyHandle);
        const hashBuffer = Buffer.from(hash, 'hex');
        const signature = pkcs11Module.C_Sign(session, hashBuffer);
        const signatureB64 = signature.toString('base64');
        // Retrieve certificate PEM for response
        const certs = await listCertificates();
        const certInfo = certs.find(c => c.id === certificateId);
        const certPem = certInfo ? certInfo.certPem : '';
        return {
            signatureValue: signatureB64,
            algorithm: 'SHA256withRSA',
            certChainPem: certPem,
        };
    } finally {
        // Logout and close session
        try { pkcs11Module.C_Logout(session); } catch (_) { }
        pkcs11Module.C_CloseSession(session);
    }
}

/**
 * Sign multiple SHA-256 hashes using the specified certificate's private key.
 * This is used for batch processing in a single token session/PIN entry.
 *
 * @param {string[]} hashes - Array of hex-encoded SHA-256 hashes
 * @param {string} certificateId - ID of the certificate to use
 * @returns {object[]} Array of results matching the input hashes order
 */
async function signHashes(hashes, certificateId) {
    if (process.env.PMLIO_MOCK_PKCS11 === 'true' || process.env.NODE_ENV === 'test') {
        return hashes.map(hash => {
            try {
                const res = getMockSignature(hash, certificateId);
                return { hash, status: 'OK', signatureValue: res.signatureValue, algorithm: res.algorithm, certChainPem: res.certChainPem };
            } catch (err) {
                return { hash, status: 'FAIL', error: err.message };
            }
        });
    }

    if (!isInitialized || !pkcs11Module) {
        throw new Error('PKCS#11 not initialized');
    }

    const slot = pkcs11Module.C_GetSlotList(true)[0];
    const session = pkcs11Module.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    try {
        const tokenInfo = pkcs11Module.C_GetTokenInfo(slot);
        const hasProtectedAuth = (tokenInfo.flags & 0x100) !== 0;
        if (hasProtectedAuth) {
            pkcs11Module.C_Login(session, pkcs11js.CKU_USER, null);
        } else {
            const pin = process.env.PMLIO_PKCS11_PIN || '';
            pkcs11Module.C_Login(session, pkcs11js.CKU_USER, pin);
        }
        const idBuffer = Buffer.from(certificateId, 'hex');
        pkcs11Module.C_FindObjectsInit(session, [{ type: pkcs11js.CKO_PRIVATE_KEY, value: idBuffer }]);
        const keyHandles = pkcs11Module.C_FindObjects(session, 1);
        pkcs11Module.C_FindObjectsFinal(session);
        if (keyHandles.length === 0) {
            throw new Error('Private key not found for certificate ID');
        }
        const keyHandle = keyHandles[0];
        const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
        const results = [];
        for (const hash of hashes) {
            pkcs11Module.C_SignInit(session, mechanism, keyHandle);
            const hashBuf = Buffer.from(hash, 'hex');
            const sig = pkcs11Module.C_Sign(session, hashBuf);
            results.push({
                hash,
                status: 'OK',
                signatureValue: sig.toString('base64'),
                algorithm: 'SHA256withRSA',
                // Retrieve PEM once (reuse)
                certChainPem: (await listCertificates()).find(c => c.id === certificateId)?.certPem || '',
            });
        }
        return results;
    } finally {
        try { pkcs11Module.C_Logout(session); } catch (_) { }
        pkcs11Module.C_CloseSession(session);
    }
}

// ============================================================
// Mock data for development/testing
// ============================================================

function getMockCertificates() {
    // Mock data kept for development/testing; structure mirrors real certificate objects
    return [
        {
            id: 'mock-cert-001',
            label: 'Mock Cert 1',
            subject_cn: 'CN=Jan Novák (TEST)',
            issuer_cn: 'CN=PostSignum Qualified CA 5 (TEST)',
            is_qualified: true,
            certPem: '-----BEGIN CERTIFICATE-----\nMIIC...MOCK...\n-----END CERTIFICATE-----',
        },
        {
            id: 'mock-cert-002',
            label: 'Mock Cert 2',
            subject_cn: 'CN=PMLio s.r.o. (TEST)',
            issuer_cn: 'CN=I.CA Qualified 2 CA/RSA (TEST)',
            is_qualified: true,
            certPem: '-----BEGIN CERTIFICATE-----\nMIIC...MOCK2...\n-----END CERTIFICATE-----',
        },
    ];
}

function getMockSignature(hash, certificateId) {
    const crypto = require('crypto');

    // Generate a deterministic mock signature from the hash
    const mockKey = crypto.createHash('sha256').update('mock-private-key-' + certificateId).digest();
    const hmac = crypto.createHmac('sha256', mockKey);
    hmac.update(Buffer.from(hash, 'hex'));
    const signatureValue = hmac.digest('base64');

    return {
        signatureValue,
        algorithm: 'SHA256withRSA',
        certChainPem: [
            '-----BEGIN CERTIFICATE-----',
            'MIIC+zCCAeOgAwIBAgIUMOCKTEST...mock...certificate==',
            '-----END CERTIFICATE-----',
        ].join('\n'),
    };
}

module.exports = { initPkcs11, getReaderStatus, listCertificates, signHash, signHashes };
