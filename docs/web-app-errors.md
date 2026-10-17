# Web App Issues That Block a Mobile App

Scope: `web/` (server.py, scanner.py, app.js, index.html). Found by static reading and grep; the app was not run. `server.py`/`scanner.py` compile and `app.js` passes `node --check`, so these are design and runtime problems, not syntax errors.

Each issue says why the mobile app breaks if it is left unresolved.

## Blockers (mobile app will not work)

1. **Server only listens on loopback (`127.0.0.1`)**
   - Where: `server.py` (`--host` default, `run_server`).
   - Problem: a phone cannot reach `127.0.0.1` on your computer. The app would show nothing.
   - Fix: a hosted backend (HTTPS) or an authenticated LAN mode. Keep loopback as the default for desktop.

2. **Same-origin only, no CORS (deliberate)**
   - Where: `server.py` ~L131, L165; `app.js` uses relative `fetch('/api/...')`.
   - Problem: a native or PWA mobile client has a different origin and all API calls are refused. Relative URLs also break inside a native wrapper.
   - Fix: configurable `API_BASE_URL` in `app.js`, plus an allow-list of origins or token auth instead of blanket same-origin.

3. **No authentication on any API**
   - Where: `/api/scan`, `/api/verify-fix`, `/api/scans/history` (including DELETE).
   - Problem: the scanner probes any host you give it. Once exposed beyond loopback, anyone can use the phone-facing server as a scanning proxy (SSRF/abuse) or wipe history.
   - Fix: API keys or login, per-user rate limits, and a target allow-list or ownership check.

4. **Hardcoded demo data and fake IPs**
   - Where: `app.js` ~L20-230 (`172.28.0.x`, `*.internal.test`, preset scores 94 and 32).
   - Problem: a mobile user outside the lab sees fabricated servers that look like real results. This is also a trust problem for a security product.
   - Fix: mark demo data clearly, or load it only in "Lab mode".

5. **Scan target IP falls back to `127.0.0.1`**
   - Where: `app.js` `transformReportToServer` (~L1294); `scanner.py` ~L1020 (`src_ip="127.0.0.1"`).
   - Problem: when DNS yields no address, the UI shows the phone's/server's own loopback as the target. Scans may point at the wrong machine.
   - Fix: show "unresolved" and block the scan instead of defaulting.

## High (app is unreliable or unsafe)

6. **TLS verification disabled in scanner**
   - Where: `scanner.py` ~L583 and ~L771, `server.py` ~L297 (`verify=False`).
   - Problem: findings can be spoofed by a network attacker. On public or mobile networks this is more likely.
   - Fix: verify by default; use a separate unverified probe only for the cert-inspection test, and label it.

7. **Blocking sockets/timeouts too short for mobile networks**
   - Where: `scanner.py` timeouts of 1.2s to 2.5s; `server.py` uses `http.server` (threaded, no async streaming).
   - Problem: slow cellular links produce false "unreachable" or "vulnerable" results. A long scan blocks a request thread.
   - Fix: job-based API (start scan, poll or stream status), longer and configurable timeouts, retry.

8. **Scan history stored only in `localStorage` + local SQLite**
   - Where: `app.js` ~L390-430; `data/processed/twin/live_scans.db`.
   - Problem: no sync across devices; browser storage can be cleared or blocked and is not available in a native app. Silent `console.warn` hides the loss.
   - Fix: store history server-side per user; surface storage errors in the UI.

9. **Broad `except Exception` swallows failures**
   - Where: `server.py` (L92, 105, 224, 238, 283, 337, 393), `scanner.py` (many, e.g. L372, 432, 781, 790).
   - Problem: a failed test can look like a passed test. For a security score, a silent failure gives a false sense of safety.
   - Fix: return an explicit "test errored" status and exclude it from the score.

10. **Score is binary-classed from threshold only**
    - Where: `app.js` `trafficClass: report.security_score >= 80 ? 'benign' : 'malicious'`.
    - Problem: an unreachable host or a failed scan can be labelled "malicious" or "benign" purely from a number.
    - Fix: add an "unknown/incomplete" state.

## Medium (mobile UX and robustness)

11. **No PWA files** (no manifest, no service worker) in `web/`. The site cannot be installed or run offline. Add `manifest.webmanifest`, icons and a service worker.
12. **Layout is not verified for small screens.** There is a viewport meta tag, but `styles.css` (1287 lines) and the 7-test dashboard were not checked at phone width. Test on 360px and add touch targets of 44px or more.
13. **Heavy `innerHTML` rendering** (`app.js` L517, 633, 742, 1058). There is an `esc()` helper, but every new field must use it, or the app is open to XSS from scanned server strings. Prefer `textContent` or a template library.
14. **No push notifications or background scans.** A mobile security app is expected to alert on changes. Needs a backend job queue plus FCM/APNs or web push.
15. **No error/offline screen.** `fetch` failures to `/api/status` and `/api/scan` need a visible "server unreachable" state and a retry button.
16. **Ethics/consent notice is only in the README.** The app needs a first-run consent screen ("scan only networks you are authorized to test") before mobile store release.
17. **Research modules not packaged.** `server.py` imports `veritas` code via `sys.path` (L29-36) and needs Python, the twin DB and optional Ollama. A phone cannot run this, so it needs a deployable backend (Docker) with a documented API.

## Suggested fix order
1 and 2 (reachable API), then 3 (auth), then 6 and 9 (scan correctness), then 4 and 5 (honest data), then 7 and 8, then 11-17.
