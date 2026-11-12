# Veritas Sentinel — mobile app

Expo (React Native + TypeScript) client for the Veritas backend. iOS, Android and web from one codebase.

| Tab | What it does |
|-----|--------------|
| **Scan** | Runs the live security scan against a host you are authorised to test; shows score, verdict and every test with its fix |
| **History** | Saved scans from the server (pull to refresh, clear) |
| **ML Detector** | Shows the trained model's card (with confidence intervals and caveats); scores a PCAP upload or pasted flow features; per-flow explanations (which features pushed toward malicious/benign) |
| **Settings** | Server address + API key (stored in the device keychain); "Test connection" checks both |

## Run it

```bash
# 1. backend (from the repo root)
export VERITAS_API_KEY="$(openssl rand -hex 24)"
veritas-api --host 0.0.0.0 --no-browser          # phones need a non-loopback bind

# 2. app
cd mobile
npm install
npx expo start                                    # scan the QR code with Expo Go
```

In **Settings** enter `<your computer's LAN IP>:8000` and the API key. Android emulator: `10.0.2.2:8000`.

## Develop / verify

```bash
npm run typecheck      # tsc --noEmit (strict)
npm test               # API-client unit tests (jest-expo)
npm run export:web     # full Metro bundle of every screen
```

## Notes

- The app only ever talks to `/api/v1/*`; the full contract is the server's `/docs` page.
- Cleartext HTTP is enabled for LAN development (`usesCleartextTraffic`, iOS local-networking exception).
  For anything beyond your own LAN, put the backend behind HTTPS — the API key is a request header.
- Native builds (`eas build`) and store submission need an Expo account and signing credentials; not set up here.
- The 4-tab structure and styling are a functional first pass, ready for UI/UX work.
