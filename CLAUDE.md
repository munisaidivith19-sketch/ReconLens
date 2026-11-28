# CLAUDE.md: ReconLens project rules

Future sessions working in this repository must follow these rules.

==================================================
1. WHAT RECONLENS IS
==================================================
ReconLens is a PASSIVE attack-surface analysis web app for bug bounty hunters and security teams. A logged-in user enters a domain, confirms they are authorized to test it, and ReconLens runs passive OSINT checks:
- DNS records, WHOIS (via RDAP), subdomains from certificate transparency (crt.sh)
- TLS certificate and protocol checks, HTTP security headers, cookie flags, WAF/CDN detection
- Email security (SPF, DMARC, DKIM): can the domain be spoofed in phishing emails?
- Tech stack and version detection
- CVEs for detected versions (NVD), enriched with CISA KEV ("actively exploited") and FIRST EPSS (exploit probability)
- VirusTotal domain reputation
- GET/POST endpoint discovery from homepage forms and Wayback Machine archived URLs
- robots.txt and sitemap.xml review
- JavaScript analysis of the homepage and the same-site scripts it loads (secrets masked, buckets, API routes); found URLs are listed, never requested
- CDN bypass / origin hints from DNS answers already collected
- Vulnerable JS libraries (Retire.js data, Apache-2.0, in app/data/retirejs), Subresource Integrity, favicon hash (Shodan/FOFA pivots), lookalike domains (DNS only), MTA-STS/TLS-RPT/BIMI
- IP ownership (Team Cymru ASN over DNS), Spamhaus DBL + URLhaus (optional ABUSECH_AUTH_KEY), HSTS preload status, WordPress plugin/theme versions from ?ver= on the homepage (never probe plugin paths)
Then it calculates a 0–100 risk score and Groq writes a prioritized AI report. The user watches every stage complete live and can export the report.

==================================================
2. NON-NEGOTIABLE RULES
==================================================
- PASSIVE ONLY. This is a public hosted demo. Never send exploit payloads, never brute-force, never port-scan, never fuzz parameters, never request discovered endpoints. Only fetch what a normal browser visit or public data source provides.
- Every outbound request to a user-supplied target goes through the SSRF guard (backend/app/core/ssrf_guard.py). No exceptions.
- Secrets come only from environment variables. Never commit real keys; commit only .env.example files with key names.
- Each scanner is one file in backend/app/scanners/ and follows the interface in base.py.
- A failing scanner never crashes a scan; its stage is marked failed with a reason.
- Users must confirm authorization (scope confirmation) before a scan starts; store the confirmation and timestamp with the scan.
- Install the latest stable versions of all packages; do not pin versions from memory.

==================================================
3. TECH STACK
==================================================
Backend:
- Python 3.13, FastAPI, Pydantic v2, pydantic-settings
- MongoDB Atlas via PyMongo's async API (do NOT use Motor; it is deprecated)
- httpx (HTTP), dnspython (DNS), cryptography (TLS cert parsing)
- PyJWT (auth tokens), pwdlib with argon2 (password hashing)
- groq (official Groq Python SDK)
- uv for local dependency management; commit requirements.txt exported from uv because Render runs pip install -r requirements.txt
- ruff (lint/format), pytest, pytest-asyncio, respx (HTTP mocking)

Frontend:
- React 19, Vite, TypeScript
- Tailwind CSS v4 via @tailwindcss/vite (no tailwind.config.js needed)
- React Router, TanStack Query, lucide-react icons, recharts (risk gauge/charts)

External data sources (all free):
- crt.sh, RDAP, NVD API 2.0 (free key), CISA KEV JSON feed, FIRST EPSS API, VirusTotal API v3 (free key), Wayback Machine CDX API, Shodan InternetDB (free, keyless, non-commercial), Groq API, enthec/webappanalyzer fingerprint data (open-source Wappalyzer fork; check its license and add attribution), Retire.js jsrepository.json (Apache-2.0, attributed in app/data/retirejs/NOTICE.md)

==================================================
4. DEPLOYMENT CONSTRAINTS (Render free tier + MongoDB Atlas M0)
==================================================
- 512 MB RAM, 0.1 CPU: keep memory low; load fingerprint data once at startup.
- No free background workers: no Celery or Redis. Scans run as asyncio background tasks inside the FastAPI process, max 2 concurrent scans (asyncio.Semaphore).
- The service sleeps after 15 minutes idle and the disk is wiped on restart: store everything in MongoDB; on startup, mark scans left "running" as "interrupted".
- Atlas M0 has 512 MB storage: use TTL indexes to expire old data.
- API limits: VirusTotal free = 4 requests/min, 500/day; NVD has rate limits even with a key. Cache results and rate-limit calls.


==================================================
DEVELOPMENT NOTES
==================================================
- Backend: `cd backend && uv sync && uv run uvicorn app.main:app --reload`. Tests: `uv run pytest`. Lint: `uv run ruff check . && uv run ruff format --check .`
- After changing dependencies run `uv export --no-hashes --no-dev --format requirements-txt -o requirements.txt`.
- Frontend: `cd frontend && npm ci && npm run dev`. Build: `npm run build`.
- All outbound HTTP (target sites AND third-party APIs) uses `SafeHttpClient` from `app/core/ssrf_guard.py`; TLS probes use `ssrf_guard.tls_handshake`. Never import httpx elsewhere for network calls. `SafeHttpClient.post_form` exists only for fixed third-party APIs (URLhaus); never POST to a scan target. The one exception is the Groq SDK in `app/services/ai_report.py`, which only talks to the fixed Groq API host (never a user-supplied target).
- Abuse controls: per-user daily quota (`DAILY_SCAN_LIMIT`), per-IP limits on login/register and on new scans (`app/core/rate_limit.py`), `MAX_CONCURRENT_SCANS` semaphore, and scope confirmation stored on every scan (including cached clones).
- Tests never touch the network: patch `ssrf_guard._dns_lookup` (fixture `public_dns`) and mock HTTP with respx against the resolved IP.
- API keys (`rl_` prefix, SHA-256 hashed, `app/api/keys.py`) authenticate scan endpoints via `deps._resolve`; key management uses `SessionUser`, which rejects keys. Batches reuse `_start_scan` in `app/api/scans.py`, so every domain goes through the same validation, quota and cache.
- Frontend styling: glassmorphism / liquid-glass tokens in `src/index.css`; use semantic tokens (`text-muted`, `bg-glass`, `.glass`, `.btn`), never raw colours in components.
