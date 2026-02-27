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

Pro vývoj lokálně se často mění JWT podepisovací klíče na backendu. Abyste nemuseli pokaždé dělat reinstalaci/stažení helperu, můžete mu vložit aktuální veřejný klíč přes proměnnou prostředí. Zkopírujte obsah `storage/app/signing/jwt-public.pem` z backendu a nastavte ho jako env variable.

```bash
# Instalace závislostí
npm install

# Spuštění Electron app s injektovaným aktuálním veřejným klíčem z backendu
PMLIO_JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" npm start

# Nebo pro pouhé testování (bez HW tokenu — mock mód)
npm test
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
