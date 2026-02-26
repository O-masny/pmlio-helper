/**
 * System Tray Management
 *
 * Creates a tray icon with context menu for the helper app.
 * Icon color reflects connection status.
 */
const { Tray, Menu, nativeImage, app } = require('electron');
const path = require('path');

let tray = null;

/**
 * Create the system tray icon and context menu.
 */
function createTray() {
    const iconPath = getIconPath('idle');
    const icon = nativeImage.createFromPath(iconPath);

    tray = new Tray(icon.resize({ width: 16, height: 16 }));
    tray.setToolTip('PMLio Helper — Idle');

    updateTrayMenu('idle');
}

/**
 * Update tray icon and menu based on status.
 *
 * @param {'connected' | 'error' | 'idle'} status
 */
function updateTrayStatus(status) {
    if (!tray) return;

    const iconPath = getIconPath(status);
    const icon = nativeImage.createFromPath(iconPath);
    tray.setImage(icon.resize({ width: 16, height: 16 }));

    const tooltips = {
        connected: 'PMLio Helper — Čtečka připojena',
        error: 'PMLio Helper — Chyba čtečky',
        idle: 'PMLio Helper — Čeká na čtečku',
    };
    tray.setToolTip(tooltips[status] || 'PMLio Helper');

    updateTrayMenu(status);
}

/**
 * Build and set the context menu.
 */
function updateTrayMenu(status) {
    const statusLabels = {
        connected: '🟢 Čtečka připojena',
        error: '🔴 Chyba čtečky',
        idle: '⚪ Čeká na čtečku',
    };

    const menu = Menu.buildFromTemplate([
        { label: statusLabels[status] || 'Status', enabled: false },
        { type: 'separator' },
        { label: 'Zobrazit certifikáty', click: () => showCertificates() },
        { type: 'separator' },
        {
            label: 'Ukončit',
            click: () => {
                app.quit();
            },
        },
    ]);

    tray.setContextMenu(menu);
}

/**
 * Get icon path based on status.
 */
function getIconPath(status) {
    const iconMap = {
        connected: 'tray-green.png',
        error: 'tray-red.png',
        idle: 'tray-gray.png',
    };
    return path.join(__dirname, '..', 'assets', iconMap[status] || 'tray-gray.png');
}

/**
 * Show certificates in a dialog (placeholder).
 */
function showCertificates() {
    const { dialog } = require('electron');
    const { listCertificates, getReaderStatus } = require('./pkcs11');

    const status = getReaderStatus();
    if (!status.readerConnected) {
        dialog.showMessageBox({
            type: 'warning',
            title: 'PMLio Helper — Certifikáty',
            message: 'Žádná čtečka není připojena',
            detail: 'Připojte USB token / čtečku čipových karet a zkuste to znovu.',
        });
        return;
    }

    listCertificates()
        .then(certs => {
            const message = certs.length > 0
                ? certs.map(c => `• ${c.subject_cn} (${c.issuer_cn})`).join('\n')
                : 'Žádné certifikáty nalezeny na tokenu.';

            dialog.showMessageBox({
                type: 'info',
                title: 'PMLio Helper — Certifikáty',
                message: 'Dostupné certifikáty:',
                detail: message,
            });
        })
        .catch(err => {
            dialog.showMessageBox({
                type: 'error',
                title: 'PMLio Helper — Chyba',
                message: 'Nepodařilo se načíst certifikáty',
                detail: err.message || 'Neznámá chyba při komunikaci s čtečkou.',
            });
        });
}

module.exports = { createTray, updateTrayStatus };
