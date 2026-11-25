# ReconLens

**Passive attack-surface analysis for bug bounty hunters and security teams.**

**Live demo:** https://reconlens-5eh4.onrender.com (free tier, so the first request may take 30–60 seconds while the server wakes up)

Enter a domain you're authorized to test. ReconLens gathers public signals, matches exposed software versions to known vulnerabilities, scores the risk from 0 to 100, and writes a prioritized analyst report. You watch every stage finish live and can export the result as JSON or PDF.

> ReconLens is **passive only**. It never sends exploit payloads, brute-forces, port-scans, fuzzes parameters or requests the endpoints it discovers. It only fetches what a normal browser visit or a public data source would provide.

---

## What it does

| Check | Source | What you learn |
|---|---|---|
| DNS records | Public DNS | A/AAAA/CNAME/MX/NS/TXT/CAA; missing CAA |
| Registration | RDAP (via rdap.org) | Registrar, creation and expiry dates |
| Subdomains | crt.sh certificate transparency | Subdomains, flagged ones worth reviewing (dev, staging, admin…) |
| TLS | One handshake to port 443 | Trust, hostname match, expiry, protocol, legacy TLS 1.0/1.1 |
| HTTP security | One homepage GET | Security headers, cookie flags, HTTPS redirect, WAF/CDN |
| Email security | Public DNS | SPF, DMARC, common DKIM selectors, plus a plain-language "can this domain be spoofed?" verdict |
| Tech stack | Homepage response + webappanalyzer fingerprints | Technologies and exposed versions |
| CVEs | NVD API 2.0 | CVEs for detected **versions** only, enriched with CISA KEV ("actively exploited") and FIRST EPSS (exploit probability) |
| Reputation | VirusTotal v3 | Engine detections, categories, reputation |
| Endpoints | Homepage forms + Wayback Machine CDX | Form actions/methods, archived paths and GET parameter names (listed, never requested) |
| robots.txt / sitemap | The site itself | Disallowed paths, sitemap size |

On top of these checks it produces:
- **A risk score (0–100).** Weighted by severity, with bonuses for spoofable email, expired TLS or domain, missing HSTS/CSP, no HTTPS, malicious reputation and KEV-listed CVEs. The top contributing factors are shown.
- **An AI report from Groq.** It contains an executive summary, prioritized findings (why each matters, how it could be abused at a high level, how to fix it), likely attack paths and next steps. The report is grounded in the scan facts, and any CVE IDs it mentions must appear in those facts. If Groq is unavailable, a deterministic template report is used instead.

## What it does *not* do

- It doesn't do active scanning of any kind: no port scans, no directory brute-forcing, no parameter fuzzing, no payloads, no exploit verification.
- It doesn't request the endpoints, archived URLs or subdomains it discovers.
- It doesn't scan IP addresses, internal or reserved ranges, non-standard ports, or hosts that resolve to non-public addresses.
- It doesn't confirm vulnerabilities. CVE matches are based on advertised versions, which may be backported or wrong, so verify every result before you report it.

## Architecture

```
                       ┌───────────────────────────────┐
   Browser             │  React 19 + Vite (static)     │
   ───────────────────▶│  Render static site + CSP     │
                       └──────────────┬────────────────┘
                                      │ HTTPS + JWT (Bearer)
                       ┌──────────────▼────────────────┐
                       │  FastAPI (Render web service) │
                       │  auth · quotas · scans API    │
                       │                               │
                       │  scan_runner (asyncio tasks,  │
                       │  max 2 concurrent scans)      │
                       │    ├─ 11 scanners (parallel,  │
                       │    │   dependency-ordered)    │
                       │    ├─ risk_score              │
                       │    └─ ai_report ──────────────┼──▶ Groq API
                       │                               │
                       │  ssrf_guard.SafeHttpClient    │
                       │  (every outbound request)     │
                       └──────┬─────────────────┬──────┘
                              │                 │
               ┌──────────────▼───┐   ┌─────────▼──────────────────────────┐
               │ MongoDB Atlas M0 │   │ Target site (homepage, robots,     │
               │ users · scans ·  │   │ TLS) + public sources: crt.sh,     │
               │ caches (TTL)     │   │ RDAP, NVD, KEV, EPSS, VirusTotal,  │
               └──────────────────┘   │ Wayback Machine                    │
                                      └────────────────────────────────────┘
```

### Security design

- **SSRF guard** (`backend/app/core/ssrf_guard.py`) handles every outbound request.
  - It normalizes the target: IDN to punycode, and it rejects IPs, numeric IP tricks, credentials, other schemes and ports other than 80/443.
  - It resolves **all** A/AAAA records and blocks the target if any of them is non-public.
  - It connects to the validated IP directly, with the correct Host header and SNI, so DNS rebinding can't redirect a request.
  - It follows redirects manually and re-validates every hop.
  - It caps response size, ignores proxy environment variables and drops cookies.
- **Authentication.**
  - Passwords are hashed with Argon2 (pwdlib).
  - Tokens are short-lived HS256 JWTs with a pinned algorithm and required claims (issuer, audience, expiry).
  - Error messages are generic, and login timing is equalized.
- **Abuse controls.**
  - Each user has a daily scan quota.
  - Per-IP limits apply to login, registration and new scans.
  - At most 2 scans run at once.
  - Repeat scans of a domain within 24 h reuse the cached results.
  - Scope confirmation and its timestamp are stored on every scan.
- **API hardening.**
  - CORS is an exact-origin allowlist.
  - Security headers are set on every response, and the Server header is removed.
  - Request bodies are limited to 16 KB.
  - OpenAPI/docs are disabled.
  - All errors share one JSON shape and never include stack traces.
- **Frontend hardening.**
  - Strict Content-Security-Policy with no inline scripts.
  - Tokens live in memory and sessionStorage and expire automatically.

## Tech stack

- **Backend.**
  - Python 3.13, FastAPI, Pydantic v2, pydantic-settings
  - PyMongo async API
  - httpx, dnspython, cryptography, PyJWT, pwdlib[argon2], groq
  - Tooling: uv, ruff, pytest, pytest-asyncio, respx
- **Frontend.**
  - React 19, Vite, TypeScript, Tailwind CSS v4
  - React Router, TanStack Query, recharts, lucide-react
  - Glassmorphism design with dark and light themes, honouring reduced-motion and reduced-transparency settings, plus a print stylesheet
- **Infrastructure.**
  - Render free tier (web service + static site)
  - MongoDB Atlas M0
  - GitHub Actions CI

## Local setup

Prerequisites:
- Python 3.13 and [uv](https://docs.astral.sh/uv/)
- Node.js 22 or later
- MongoDB, either running locally or as an Atlas connection string

**Quick start:** one command sets up whatever is missing and runs both servers:

```bash
python run.py            # http://localhost:5173 opens automatically; Ctrl+C stops everything
```

Or do it manually:

```bash
git clone https://github.com/munisaidivith19-sketch/ReconLens.git
cd ReconLens

# Backend
cd backend
cp .env.example .env            # then set JWT_SECRET (and optional API keys)
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste as JWT_SECRET
uv sync
uv run uvicorn app.main:app --reload       # http://localhost:8000/api/health

# Frontend (new terminal)
cd frontend
cp .env.example .env
npm ci
npm run dev                                 # http://localhost:5173
```

Tests and linting:

```bash
cd backend && uv run pytest && uv run ruff check . && uv run ruff format --check .
cd frontend && npm run build && npx oxlint src
```

The tests never touch the network: DNS is patched, and HTTP is mocked with respx.

## Environment variables

### Backend (`backend/.env`)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `MONGODB_URI` | yes | `mongodb://localhost:27017` | Atlas: `mongodb+srv://…` |
| `MONGODB_DB` | no | `reconlens` | |
| `JWT_SECRET` | **yes** | none | At least 32 characters, random |
| `JWT_EXPIRE_MINUTES` | no | `60` | |
| `GROQ_API_KEY` | recommended | none | Without it, a template report is used |
| `GROQ_MODEL` | no | `openai/gpt-oss-120b` | Any Groq model with JSON mode |
| `VT_API_KEY` | recommended | none | Without it, the reputation check is skipped |
| `NVD_API_KEY` | recommended | none | Without it, NVD's much lower anonymous rate limit applies |
| `FRONTEND_ORIGIN` | **yes** in prod | `http://localhost:5173` | Exact origin(s), comma-separated |
| `DAILY_SCAN_LIMIT` | no | `10` | New scans per user per UTC day |
| `MAX_CONCURRENT_SCANS` | no | `2` | |
| `TRUSTED_PROXY_HOPS` | no | `1` | Proxies that append to `X-Forwarded-For` (Render: 1; local: 0) |
| `LOG_LEVEL` | no | `INFO` | |

### Frontend (`frontend/.env`)

| Variable | Notes |
|---|---|
| `VITE_API_URL` | The backend base URL, with no trailing slash. It is fixed at build time. |

## Deploying to Render

`render.yaml` is a Render Blueprint that defines both services.

1. **Create the database.** In MongoDB Atlas:
   - Create a free **M0** cluster.
   - Create a database user.
   - Under *Network Access*, allow `0.0.0.0/0`. Render's free tier has no static outbound IPs.
   - Copy the `mongodb+srv://` connection string.
2. **Get API keys.**
   - [Groq](https://console.groq.com/keys)
   - [VirusTotal](https://www.virustotal.com/gui/my-apikey) (free account)
   - [NVD](https://nvd.nist.gov/developers/request-an-api-key)
3. **Create the Blueprint.** In Render, go to **New → Blueprint**, select this repository, and Render reads `render.yaml`.
4. **Fill in the secrets** marked `sync: false`:
   - `MONGODB_URI`
   - `GROQ_API_KEY`, `VT_API_KEY`, `NVD_API_KEY`
   - `FRONTEND_ORIGIN`, for example `https://reconlens.onrender.com`

   `JWT_SECRET` is generated automatically.
5. **Check the service URLs.** If Render assigns URLs other than `reconlens-api.onrender.com` and `reconlens.onrender.com`, update these three values to match, then redeploy the static site:
   - `VITE_API_URL`
   - the `connect-src` entry in the frontend CSP header in `render.yaml`
   - `FRONTEND_ORIGIN`
6. **Verify the deployment.**
   - `https://<api>/api/health` should return `{"status":"ok","database":"ok"}`.
   - Open the frontend, register, and scan a domain you own.

Free-tier notes:
- The API sleeps after 15 minutes idle. The first request after that takes about 30–60 s, and the UI shows a wake-up notice while it waits.
- Scans that were running during a restart are marked `interrupted`.
- Old data expires through TTL indexes: scans after 30 days, caches after 24 h.

## Attributions and licences

| Source | Use | Terms |
|---|---|---|
| [crt.sh](https://crt.sh) (Sectigo) | Certificate transparency search | Free public service; be gentle |
| [RDAP](https://about.rdap.org) / rdap.org bootstrap | Registration data | Public registry data (IANA bootstrap) |
| [NIST NVD](https://nvd.nist.gov) | CVE data | *This product uses the NVD API but is not endorsed or certified by the NVD.* |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited CVEs | Public domain (U.S. Government work) |
| [FIRST EPSS](https://www.first.org/epss) | Exploit prediction scores | Free use with attribution to FIRST |
| [VirusTotal](https://www.virustotal.com) | Domain reputation | Public API terms; free tier is non-commercial |
| [Internet Archive Wayback Machine](https://web.archive.org) | Archived URLs (CDX API) | Internet Archive terms of use |
| [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) | Technology fingerprints (`backend/app/data/fingerprints`) | **GPL-3.0**: see the `LICENSE` and `NOTICE.md` in that directory |
| [Groq](https://groq.com) | AI report generation | Groq API terms |

ReconLens's own code is MIT-licensed (see `LICENSE`). The bundled fingerprint data stays under GPL-3.0.

## Responsible use

- Only scan domains **you own or are explicitly authorized to test**, such as targets in scope for a bug bounty programme or covered by written permission. You must confirm this before every scan, and the confirmation is stored with its timestamp.
- Even passive reconnaissance can breach a programme's rules. Read its policy first.
- Treat the results as leads, not proof. Verify them manually and within scope before reporting.
- Report vulnerabilities in ReconLens itself privately through GitHub security advisories on this repository.

See the in-app **Responsible use** page (`/terms`) for the full policy.

## Roadmap (v2)

- **Local active mode.** Optional, self-hosted only, never on the public demo: Nmap service detection and Nuclei templates, gated behind explicit scope files.
- **Retire.js.** Detect vulnerable client-side JavaScript libraries from the script URLs and versions already collected.
- **Shodan InternetDB.** Free, passive lookup of open ports and CVEs already indexed for the resolved IPs.
- **security.txt.** Fetch and parse `/.well-known/security.txt` to show disclosure contacts and policy.
- Scheduled re-scans with diffs, and webhook notifications.
