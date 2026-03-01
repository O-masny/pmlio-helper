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
 * Dynamic discovery of PKCS#11 libraries.
 * Scans known locations for Czech Market & EU Tokens (I.CA, ProID, SafeNet, Bit4Id, etc.)
 */
function findPkcs11Libs() {
    const fs = require('fs');
    const path = require('path');
    const libs = [];

    // 1. Environment Variable Override (Highest Priority)
    if (process.env.PMLIO_PKCS11_LIB && fs.existsSync(process.env.PMLIO_PKCS11_LIB)) {
        libs.push(process.env.PMLIO_PKCS11_LIB);
    }

    // 2. Windows Libraries (Czech Market & Common EU Tokens)
    if (process.platform === 'win32') {
        const sys32 = process.env.windir ? path.join(process.env.windir, 'System32') : 'C:\\Windows\\System32';
        const sysWow = process.env.windir ? path.join(process.env.windir, 'SysWOW64') : 'C:\\Windows\\SysWOW64';

        const winConfigDirs = [sys32, sysWow];

        // Comprehensive list of DLL names typically deployed to System32 by token installers
        const commonDlls = [
            'eTPKCS11.dll', 'eToken.dll',                 // SafeNet / eToken
            'IDPrimePKCS11.dll', 'IDPrimePKCS1164.dll',   // SafeNet / Thales
            'bit4ipki.dll', 'bit4opki.dll', 'bit4xpki.dll', // Bit4Id / miniLector
            'icapki.dll', 'IcaRS11.dll', 'IcaRS11_64.dll', 'IcaPkcs11.dll', // I.CA (Czech)
            'proid11.dll', 'proid11_64.dll', 'cryptoos11.dll', // ProID / Monet+ (Czech)
            'gclib.dll', 'siecap11.dll',                  // Gemalto
            'aetpkss1.dll', 'aetpkss1_64.dll',            // SafeSign / AET
            'ASEPKCS.dll',                                // Athena
            'opensc-pkcs11.dll',                          // OpenSC generic
            'cvP11.dll',                                  // Cryptovision
        ];

        winConfigDirs.forEach(dir => {
            commonDlls.forEach(dll => {
                const fullPath = path.join(dir, dll);
                if (fs.existsSync(fullPath)) libs.push(fullPath);
            });
        });

        // Common specific sub-paths in Program Files
        const prog = process.env.ProgramFiles || 'C:\\Program Files';
        const prog86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';

        const specificPaths = [
            'SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS11.dll',
            'SafeNet\\Authentication\\SAC\\IDPrimePKCS11.dll',
            'OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
            'Bit4Id\\miniLector\\bit4ipki.dll',
            'I.CA\\SecureStore\\icapki.dll',
            'ProID\\proid11.dll',
        ];

        [prog, prog86].forEach(baseDir => {
            specificPaths.forEach(sp => {
                const fullPath = path.join(baseDir, sp);
                if (fs.existsSync(fullPath)) libs.push(fullPath);
            });
        });
    }

    // 3. macOS Libraries
    else if (process.platform === 'darwin') {
        [
            '/usr/local/lib/opensc-pkcs11.so',
            '/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib',
            '/usr/local/lib/libeToken.dylib',
            '/usr/local/lib/libbit4ipki.dylib',
        ].forEach(p => { if (fs.existsSync(p)) libs.push(p); });
    }

    // 4. Linux Libraries
    else if (process.platform === 'linux') {
        [
            '/usr/lib/opensc-pkcs11.so',
            '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
            '/usr/lib/libeToken.so',
            '/usr/lib/libbit4ipki.so',
        ].forEach(p => { if (fs.existsSync(p)) libs.push(p); });
    }

    // Return unique values only
    return [...new Set(libs)];
}

/**
 * Initialize PKCS#11 module — detect reader and token dynamically.
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

        const libsToTry = findPkcs11Libs();
        let scannedCount = libsToTry.length;

        if (scannedCount === 0) {
            console.warn('[PKCS#11] No known PKCS#11 libraries found on this system');
            return false;
        }

        console.log(`[PKCS#11] Discovered ${scannedCount} potential libraries. Probing...`);

        for (const lib of libsToTry) {
            try {
                pkcs11Module.load(lib);
                pkcs11Module.C_Initialize();

                // Check for slots (readers)
                const slots = pkcs11Module.C_GetSlotList(false);
                if (slots.length > 0) {
                    const slotInfo = pkcs11Module.C_GetSlotInfo(slots[0]);

                    readerStatus = {
                        readerConnected: true,
                        tokenPresent: (slotInfo.flags & 0x02) !== 0, // CKF_TOKEN_PRESENT
                        readerName: slotInfo.slotDescription?.trim() || 'Unknown Reader',
                        activeLibrary: lib
                    };

                    console.log(`[PKCS#11] Success! Bound to: ${lib}`);
                    console.log(`[PKCS#11] Reader: ${readerStatus.readerName}, Token Present: ${readerStatus.tokenPresent}`);
                    isInitialized = true;
                    return true;
                } else {
                    // This library works but has no slots attached. We close it safely and check the next one.
                    try { pkcs11Module.C_Finalize(); } catch (_) { }
                    try { pkcs11Module.close(); } catch (_) { }
                }
            } catch (e) {
                // If it fails to load or init, silently close and continue trying others
                try { pkcs11Module.close(); } catch (_) { }
                continue;
            }
        }

        console.warn(`[PKCS#11] Probed ${scannedCount} libraries, but no reader was found.`);
        return false;
    } catch (err) {
        console.error('[PKCS#11] Core init failed:', err.message);
        return false;
    }
}

/**
 * Get current reader status.
 */
function getReaderStatus() {
    if (process.env.PMLIO_MOCK_PKCS11 === 'true' || process.env.NODE_ENV === 'test') {
        return {
            readerConnected: true,
            tokenPresent: true,
            readerName: 'Mock SmartCard Reader (PMLIO_MOCK_PKCS11)',
        };
    }
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
        // Find all certificate objects (CKO_CERTIFICATE)
        pkcs11Module.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_CERTIFICATE }
        ]);
        const handles = pkcs11Module.C_FindObjects(session, 100);
        pkcs11Module.C_FindObjectsFinal(session);
        const certs = handles.map(handle => {
            const getAttr = (type) => {
                try {
                    const res = pkcs11Module.C_GetAttributeValue(session, handle, [{ type }]);
                    return res[0].value;
                } catch (e) {
                    console.warn(`[PKCS#11] Optional attribute ${type} not found for handle ${handle}`);
                    return null;
                }
            };

            /**
             * Safely convert a PKCS#11 buffer to a human-readable UTF-8 string.
             * Strips null bytes and non-printable characters to prevent garbled output.
             */
            const safeBufferToUtf8 = (buf) => {
                if (!buf || !Buffer.isBuffer(buf)) return null;
                const str = buf.toString('utf8').replace(/\0/g, '').trim();
                // Check if result contains mostly printable ASCII/UTF-8
                const printable = str.replace(/[^\x20-\x7E\u00C0-\u024F\u0400-\u04FF]/g, '');
                return printable.length > str.length * 0.5 ? str : null;
            };

            const idBuf = getAttr(pkcs11js.CKA_ID);
            const subjectBuf = getAttr(pkcs11js.CKA_SUBJECT);
            const issuerBuf = getAttr(pkcs11js.CKA_ISSUER);
            const valueBuf = getAttr(pkcs11js.CKA_VALUE);
            const labelBuf = getAttr(pkcs11js.CKA_LABEL);
            const trustedBuf = getAttr(pkcs11js.CKA_TRUSTED);

            const id = idBuf ? idBuf.toString('hex') : 'unknown';
            const der = valueBuf;
            const pem = der ? derToPem(der) : '';
            const label = labelBuf ? safeBufferToUtf8(labelBuf) || 'Unnamed Certificate' : 'Unnamed Certificate';
            const trusted = trustedBuf ? !!trustedBuf.readUInt8(0) : false;

            let parsedSubject = 'Unknown Subject';
            let parsedIssuer = 'Unknown Issuer';

            if (pem) {
                try {
                    const crypto = require('crypto');
                    if (crypto.X509Certificate) {
                        const x509 = new crypto.X509Certificate(pem);
                        const parseDN = (dnString) => {
                            if (!dnString) return '';
                            const parts = dnString.split('\n');
                            for (const p of parts) {
                                if (p.trim().startsWith('CN=')) {
                                    return p.trim().substring(3);
                                }
                            }
                            return dnString.replace(/\n/g, ', ');
                        };
                        parsedSubject = parseDN(x509.subject) || label || 'Unknown Subject';
                        parsedIssuer = parseDN(x509.issuer) || 'Unknown Issuer';
                    } else {
                        const forge = require('node-forge');
                        const cert = forge.pki.certificateFromPem(pem);
                        const getCN = (fields) => {
                            const attrs = cert[fields] ? cert[fields].attributes : [];
                            const cnAttr = attrs.find(a => a.shortName === 'CN' || a.name === 'commonName');
                            return cnAttr ? cnAttr.value : null;
                        };
                        parsedSubject = getCN('subject') || label || 'Unknown Subject';
                        parsedIssuer = getCN('issuer') || 'Unknown Issuer';
                    }
                } catch (e) {
                    console.warn(`[PKCS#11] Failed to parse X509 properties: ${e.message}`);
                    // Fallback: use label for subject, never raw buffer
                    parsedSubject = label || 'Unknown Subject';
                    parsedIssuer = 'Unknown Issuer';
                }
            } else {
                // No DER value available — use label as subject, never raw buffer
                parsedSubject = label || 'Unknown Subject';
                parsedIssuer = 'Unknown Issuer';
            }

            return {
                id,
                label,
                subject_cn: parsedSubject,
                issuer_cn: parsedIssuer,
                is_qualified: trusted,
                certPem: pem,
            };
        }).filter(Boolean);
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
        pkcs11Module.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
            { type: pkcs11js.CKA_ID, value: idBuffer }
        ]);
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
        pkcs11Module.C_FindObjectsInit(session, [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
            { type: pkcs11js.CKA_ID, value: idBuffer }
        ]);
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

// ============================================================
// Periodic re-scan — detect tokens plugged in after startup
// ============================================================
let rescanInterval = null;

/**
 * Start periodic re-scanning for newly connected readers/tokens.
 * Runs every `intervalMs` (default 5 s). Stops once a token is found.
 */
function startRescan(intervalMs = 5000) {
    if (rescanInterval) return; // already running
    console.log(`[PKCS#11] Starting periodic re-scan every ${intervalMs / 1000}s`);
    rescanInterval = setInterval(async () => {
        if (isInitialized && readerStatus.tokenPresent) {
            // Token already detected — stop polling
            clearInterval(rescanInterval);
            rescanInterval = null;
            return;
        }
        console.log('[PKCS#11] Re-scanning for readers/tokens…');
        const found = await initPkcs11();
        if (found && readerStatus.tokenPresent) {
            console.log('[PKCS#11] Token detected on re-scan!');
            clearInterval(rescanInterval);
            rescanInterval = null;
            // Notify tray if available (lazy-require to avoid circular deps)
            try {
                const { updateTrayStatus } = require('./tray');
                updateTrayStatus('connected');
            } catch (_) { /* tray not initialised yet */ }
        }
    }, intervalMs);
}

function stopRescan() {
    if (rescanInterval) {
        clearInterval(rescanInterval);
        rescanInterval = null;
    }
}

module.exports = { initPkcs11, getReaderStatus, listCertificates, signHash, signHashes, startRescan, stopRescan };
