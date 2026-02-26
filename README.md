# PMLio Desktop Signing Helper

Standalone desktopová aplikace pro kryptografické podepisování PML evidenčních záznamů pomocí USB tokenů (SafeNet, Bit4Id).

## Architektura

```
Browser (Flutter Web SPA)
    │
    │  HTTP REST (localhost:14725)
    ▼
┌─────────────────────┐
│   pmlio-helper      │
│   (Electron + Node) │
│                     │
│  Express Server     │
│  ├─ /health         │
│  ├─ /certificates   │
│  └─ /sign           │
│                     │
│  PKCS#11 Bridge     │
│  └─ USB Token ←─────┤── PIN dialog (nativní OS)
└─────────────────────┘
```

## Rychlý start (Development)

```bash
# Instalace závislostí
npm install

# Spuštění testů (bez HW tokenu — mock mód)
npm test

# Spuštění Electron app
npm start
```

## API Endpoints

### `GET /health`
```json
{ "status": "ok", "version": "1.0.0", "reader_connected": true, "token_present": true }
```

### `GET /certificates`
Vrátí pole certifikátů na HW tokenu.

### `POST /sign`
```json
// Request
{ "challenge_jwt": "eyJhbGci...", "certificate_id": "cert-abc123" }

// Response
{ "signature_value": "MEUCIQD...", "algorithm": "SHA256withRSA", "cert_chain_pem": "..." }
```

## Bezpečnost

- **CORS**: Pouze `*.pmlio.cz` a `localhost`
- **JWT Challenge**: `aud=pmlio-helper`, `exp=60–120s`, replay protection (JTI)
- **PIN**: Nativní OS dialog — helper nikdy nevidí PIN
- **Privátní klíč**: Nikdy neopouští USB token

## Build instalátorů

```bash
npm run build:win   # → dist/pmlio-helper.exe
npm run build:mac   # → dist/pmlio-helper.dmg
```
