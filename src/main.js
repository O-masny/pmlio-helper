/**
 * PMLio Desktop Signing Helper — Electron Main Process
 *
 * System tray application that runs a localhost HTTPS server
 * for bridging USB token signing to the PMLio web application.
 */
const { app, BrowserWindow } = require('electron');
const { createTray, updateTrayStatus } = require('./tray');
const { startServer, stopServer } = require('./server');
const { initPkcs11, getReaderStatus } = require('./pkcs11');

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

  // 1. Initialize PKCS#11 (detect readers)
  const pkcs11Ready = await initPkcs11();

  // 2. Start localhost server
  const server = await startServer();

  // 3. Create system tray
  createTray();

  // 4. Update tray based on reader status
  const status = getReaderStatus();
  updateTrayStatus(status.readerConnected ? 'connected' : 'idle');

  console.log(`[PMLio Helper] Ready. Server on https://127.0.0.1:14725`);
  console.log(`[PMLio Helper] PKCS#11: ${pkcs11Ready ? 'OK' : 'No reader found'}`);
});

app.on('window-all-closed', (e) => {
  // Don't quit when all windows closed — we're a tray app
  e.preventDefault();
});

app.on('before-quit', () => {
  stopServer();
});
