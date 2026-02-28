/**
 * PMLio Desktop Signing Helper — Electron Main Process
 *
 * System tray application that runs a localhost HTTPS server
 * for bridging USB token signing to the PMLio web application.
 */
const { app, BrowserWindow } = require('electron');
const { createTray, updateTrayStatus } = require('./tray');
const { startServer, stopServer } = require('./server');
const { initPkcs11, getReaderStatus, startRescan, stopRescan } = require('./pkcs11');

// Prevent multiple instances
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

// Hide dock icon on macOS (tray-only app)
if (process.platform === 'darwin') {
  app.dock?.hide();
}

app.whenReady().then(async () => {
  console.log('[PMLio Helper] Starting...');

  // Enable auto-start by default (tenant convenience)
  // This registers the app in Windows startup (HKCU\...\Run)
  if (!app.getLoginItemSettings().openAtLogin) {
    app.setLoginItemSettings({ openAtLogin: true });
    console.log('[PMLio Helper] Auto-start enabled (first launch).');
  }

  // 1. Initialize PKCS#11 (detect readers) — non-fatal
  let pkcs11Ready = false;
  try {
    pkcs11Ready = await initPkcs11();
  } catch (err) {
    console.warn('[PMLio Helper] PKCS#11 init failed (non-fatal):', err.message);
  }

  // 2. Start localhost server
  let server = null;
  try {
    server = await startServer();
    console.log('[PMLio Helper] Server on http://127.0.0.1:14725');
  } catch (err) {
    console.error('[PMLio Helper] Server failed to start:', err.message);
  }

  // 3. Create system tray (always — even if hardware is missing)
  createTray();

  // 4. Update tray based on reader status
  const status = getReaderStatus();
  const isMock = process.env.PMLIO_MOCK_PKCS11 === 'true' || process.env.NODE_ENV === 'test';

  setTimeout(() => {
    if (isMock) {
      updateTrayStatus('connected');
    } else {
      updateTrayStatus(server ? (status.readerConnected ? 'connected' : 'idle') : 'error');
    }
  }, 500);

  // 5. If no token found at startup, start periodic re-scan (every 5s)
  //    so hot-plugged USB tokens get picked up automatically
  if (!isMock && (!pkcs11Ready || !status.tokenPresent)) {
    startRescan(5000);
  }

  console.log(`[PMLio Helper] Ready. PKCS#11: ${isMock ? 'MOCK' : (pkcs11Ready ? 'OK' : 'No reader found — re-scan active')}`);
});

app.on('window-all-closed', (e) => {
  // Don't quit when all windows closed — we're a tray app
  e.preventDefault();
});

app.on('before-quit', () => {
  stopRescan();
  stopServer();
});
