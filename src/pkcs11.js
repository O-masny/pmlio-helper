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

    // Real PKCS#11 enumeration would happen here
    // For now, return empty until real hardware is connected
    return [];
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

    // Real PKCS#11 signing would happen here:
    // 1. Open session
    // 2. Login with PIN (PKCS#11 C_Login — triggers native OS PIN dialog)
    // 3. Find private key matching certificateId
    // 4. C_SignInit + C_Sign with CKM_SHA256_RSA_PKCS
    // 5. Return base64-encoded signature

    throw new Error('Real PKCS#11 signing not yet implemented — connect a hardware token');
}

// ============================================================
// Mock data for development/testing
// ============================================================

function getMockCertificates() {
    return [
        {
            id: 'mock-cert-001',
            subject_cn: 'Jan Novák (TEST)',
            issuer_cn: 'PostSignum Qualified CA 5 (TEST)',
            valid_from: '2025-01-01',
            valid_to: '2027-01-01',
            is_qualified: true,
        },
        {
            id: 'mock-cert-002',
            subject_cn: 'PMLio s.r.o. (TEST)',
            issuer_cn: 'I.CA Qualified 2 CA/RSA (TEST)',
            valid_from: '2025-06-01',
            valid_to: '2026-06-01',
            is_qualified: true,
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

module.exports = { initPkcs11, getReaderStatus, listCertificates, signHash };
