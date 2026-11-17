# SOCMind AI: Multi-Agent Autonomous Threat Triage & Incident Response Copilot

**Academic cybersecurity project** · Team 150 · Team Leader: Chandresh Kumar · Team Member: Kalpna Chaudhary · Mentor: Sachin Kumar Yadav

SOC analysts receive more alerts than they can read: duplicates, noise, and real attacks hidden among them. SOCMind AI
ingests alerts, normalizes and scores them, extracts and enriches indicators, groups related alerts into incidents,
builds an evidence-labelled investigation, proposes a response, and then **waits for a human decision**. Nothing is ever
executed against a real system.

## What is real and what is simulated

| Area | Status |
| --- | --- |
| Alert ingestion, normalization, storage (FastAPI + SQLAlchemy + SQLite), duplicate detection | **Real** |
| Deterministic triage scoring with an explanation | **Real** (rule based) |
| IOC extraction (IPv4/IPv6, hashes, URLs, domains) | **Real** |
| Threat-intelligence **lookups** | **Simulated by default**: a small local mock dataset, labelled `mock` and `verified: false`. **Optional live mode** (`THREAT_INTEL_PROVIDER=virustotal` plus your own API key) looks public IPs, domains and file hashes up on VirusTotal's public API. Live results are third-party verdicts and are never presented as verified. See "Threat intelligence". |
| Correlation into incidents | **Real** (shared host / IP / hash within a time window) |
| Investigation timeline and findings | **Real logic on synthetic logs**: logs come from `data/sample_logs/sample_logs.json`; no SIEM is queried. Hypotheses are keyword rules, labelled as unconfirmed. |
| Response recommendations | **Real logic**, proposals only |
| Human approval / rejection, audit trail | **Real**, persisted |
| Executing a response | **Not implemented, by design.** Approved responses can only be **simulated** (recorded, nothing run). |
| AI / LLM | **None.** All five agents are deterministic code. |
| Authentication and roles | **Real, three modes** chosen with `AUTH_MODE`: `disabled` (demo mode, no authentication), `token` (static bearer tokens with the roles viewer / analyst / approver) and `accounts` (username and password sign-in and sign-out with a session cookie). The backend enforces the roles. See "Authentication" and "Security limitations". |

> **Safety boundaries.** All data is synthetic, public or explicitly authorized test data. No real credentials or
> enterprise connections. Command-line strings in alerts are treated strictly as data and never executed. Every
> recommendation requires an explicit human decision, and even an approved one is only simulated.

## Architecture

```
React UI (Vite, :5173) ──HTTP──► FastAPI (:8000) ──► SQLite (alerts, incidents, audit_logs, user_accounts, auth_sessions, login_attempts)
                                    │
                    Triage ─► Enrichment ─► Correlation ─► Investigation ─► Response ─► [human approves/rejects] ─► [simulation]
```

Details of every stage, the state machines, concurrency guards and the audit trail: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.
Endpoint reference with examples: **[docs/API.md](docs/API.md)**.

```
backend/app/
  api/v1/        routers: alerts, incidents, pipeline + agents, audit-logs, auth (status, login, logout, me), stats/config, health
  agents/        triage, enrichment, correlation, investigation, response
  core/          auth.py (modes, roles, sessions, CSRF), config.py, clock.py, runtime.py
  services/      orchestrator, incident_service, pipeline_steps, normalization, audit, seed, log_store,
                 staleness, incident_state, threat_intel, accounts, passwords
  cli/           accounts.py: command line to create and manage sign-in accounts
  tools/         mock_intel.py (offline mock intelligence), virustotal.py (opt-in VirusTotal client)
  models/        SQLAlchemy models (incl. auth_models.py)        schemas/   Pydantic request/response models
  db/session.py  engine, sessions, and the small startup schema upgrade
backend/tests/   pytest suite (unit, API, security and end-to-end workflow tests)
frontend/src/    React app: api.js, pages/ (Dashboard, Alerts, Incidents, AgentActivity, AuditLog, Settings, Login), components/,
                 lib/ (pure helpers with unit tests: view, alertFilters, incidentFilters, auditCsv, auditLoad, session)
frontend/scripts/integration-smoke.mjs   frontend <-> backend integration test
data/            synthetic alerts and logs
docs/            ARCHITECTURE.md, API.md, SECURITY.md, KALPNA_FEATURE_RESERVATION.md
```

## Prerequisites

- Python 3.11 or newer (developed and tested with 3.14) and `pip`
- Node.js 22 or newer (tested with 24; the Docker image uses `node:24-alpine`) and `npm`
- Optional: Docker (see below; **not exercised** during the latest verification)

## Run it locally

**1. Backend**

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Windows.  macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

API: <http://localhost:8000>, interactive docs: <http://localhost:8000/docs>. The SQLite file `socmind.db` is created in
the directory you start from. (`python app/main.py` does **not** work because the `app` package is not importable that
way; use the `uvicorn` command above.)

**2. Frontend** (second terminal)

```bash
cd frontend
npm install
npm run dev
```

UI: <http://localhost:5173>. The UI expects the backend at `http://localhost:8000/api/v1`; override with
`VITE_API_BASE` in `frontend/.env.local`.

**3. Try the workflow**

(With `AUTH_MODE=accounts`, sign in first; see "Authentication" below.)

1. *Security Alerts* → **Load sample (synthetic) alerts** (nothing is loaded automatically).
2. Open an alert → **Run triage**, **Run enrichment**. The list can be filtered by severity and status and searched. **Close alert** (after a confirmation) marks the alert CLOSED and removes it from active incidents; it cannot be reopened and nothing is executed.
3. *Agent Pipeline* → **Run full pipeline**. Sample data produces 2 incidents.
4. *Correlated Incidents* → expand an incident: why the alerts were grouped, the timeline, verified facts vs mock
   intelligence vs hypotheses, and the proposed actions (each marked NOT EXECUTED). The incident list can be searched, filtered and sorted.
5. Enter your name → **Approve** or **Reject**; after approving, optionally **Run simulation (no real action)**.
6. *Audit Log* shows who did what and can be exported to CSV; *Settings* shows the backend's real configuration (read-only).

Or from the command line: `curl -X POST localhost:8000/api/v1/alerts/seed` then `curl -X POST localhost:8000/api/v1/pipeline/run`.

### Docker (provided, unverified)

`docker compose up --build` starts a **local development and demo** stack (`docker-compose.yml`). By default it runs in demo mode
(`AUTH_MODE=disabled`, no authentication), publishes its ports on `127.0.0.1` only, and keeps the SQLite database in the named volume `socmind-db`
(`docker compose down` keeps it; `docker compose down -v` deletes it). The backend container runs as the non-root user
`socmind`, and the frontend container runs the Vite dev server as the non-root user `node`. The frontend image uses Node 24,
because Node 18 is end-of-life.

The backend image sets `ENVIRONMENT=production`, and Compose lets you choose the environment explicitly. A production-like run
refuses demo mode:

```
SOCMIND_ENVIRONMENT=production AUTH_MODE=token AUTH_TOKENS='[...]' docker compose up --build
```

In a production-like run the default demo mode makes the backend exit at startup, and so does `AUTH_MODE=token` without valid tokens. Keep real tokens out of Git. `AUTH_MODE=accounts` is also accepted by the backend, and the Compose file passes the `SESSION_*` and `LOGIN_*` settings with the application's defaults, but accounts mode has not been tried in Docker. The frontend is a development server, so this Compose file is not a production deployment on its own.

**Not verified:** Docker is not installed in the environment where these files were written, so no image has been built or run.

## Configuration

Copy [`.env.example`](.env.example) to `backend/.env`. Every variable is optional. Only variables the code reads are listed:
`PROJECT_NAME`, `ENVIRONMENT`, `DEBUG`, `LOG_LEVEL`, `DATABASE_URL`, `CORS_ORIGINS`, `THREAT_INTEL_MOCK_MODE`,
`THREAT_INTEL_PROVIDER`, `AUTH_MODE`, `AUTH_TOKENS`, `SESSION_IDLE_MINUTES`, `SESSION_ABSOLUTE_HOURS`, `SESSION_COOKIE_SECURE`, `LOGIN_MAX_FAILURES`, `LOGIN_LOCK_MINUTES` and the `VIRUSTOTAL_*` settings described below. Never commit a real
`.env` (it is in `.gitignore`).

### Authentication

`AUTH_MODE=disabled` (the default) is a **demo mode with no authentication**: every action is allowed and reviewer names are
typed by the user. `AUTH_MODE=token` requires `Authorization: Bearer <token>` and gives each token a role (viewer,
analyst or approver), and the reviewer recorded on a decision is the token's name. The API refuses to start when token mode
has no valid tokens, and it refuses demo mode (`AUTH_MODE=disabled`) outside `ENVIRONMENT=development` or `test`. Roles, status codes and the token rules are in [docs/SECURITY.md](docs/SECURITY.md).

```
AUTH_MODE=token
AUTH_TOKENS=[{"name": "Ana Analyst", "role": "analyst", "token": "<at least 16 random characters>"}]
```

**Accounts (sign-in with a password).** `AUTH_MODE=accounts` shows a sign-in page (and a **Sign out** button once signed in). No account
exists at first. The page then shows **Create the first administrator account** instead of the sign-in form: a username and a password
typed twice make the first approver and sign them in. That form is offered only while there is no account at all (the server answers
`409` to it afterwards), so create the account before anyone else can reach the address. The command line does the same, and also
creates the other accounts; the password is typed at a prompt, never passed as an argument:

```
cd backend
python -m app.cli.accounts create-user --username ana.analyst --role analyst
python -m app.cli.accounts reset-password --username ana.analyst
python -m app.cli.accounts list-users
```

Sessions last 30 minutes without use and 8 hours at most. Five failed sign-ins for one name and address lock that pair for 15
minutes. The session cookie is `HttpOnly` and `SameSite=Strict`, and it is `Secure` outside development. Deploy behind HTTPS with
the frontend and the API on the same site. The full rules and their limits are in [docs/SECURITY.md](docs/SECURITY.md).

**Managing accounts and passwords (accounts mode).** Signed in as an approver, **Settings → Users** lists the accounts, creates
one (username, role, and a password typed twice) and disables or enables one. Disabling ends that account's sessions at once; you
cannot disable your own account, and the last active approver cannot be disabled. Every signed-in account can change its own
password under **Settings → Change password**: the current password is required, and the account's other sessions are signed out.
A forgotten password is handled by an approver: **Settings → Users → Reset password** (a new password typed twice, after a
confirmation) sets it, ends every session of that account and clears its sign-in lockout; the approver then gives the person the new
password in person. An approver cannot reset their own password that way, and uses **Change password** instead. The sign-in page says
"Forgot your password? Ask an approver to reset it." The same actions are available through the API (`GET /auth/users`,
`POST /auth/users`, `POST /auth/users/{username}/disable` and `/enable`, `POST /auth/users/{username}/password`, `POST /auth/password`,
`POST /auth/setup`; see [docs/API.md](docs/API.md)). Two minutes before a
session would end for inactivity, the page shows "Your session will end in 2 minutes due to inactivity" with a **Stay signed in**
button, and five minutes before the 8-hour limit it shows a notice. The Audit Log has an **Authentication events** filter (sign-in,
sign-out, account, password change and password reset events). There is **no public sign-up** (only the first-run page, once), **no
password reset by e-mail**, and **no multi-factor authentication**.

**Optional read-only guest.** `ALLOW_GUEST=true` (accounts mode only, **off by default**) adds **Continue as guest (read-only)** to the
sign-in page. A guest is a viewer called "guest" with a short-lived session and no account and no password: it can read alerts,
incidents and the audit log and can change nothing (every route that needs the analyst or approver role answers `403`), and the top
bar says "Guest (read-only)". It is meant for a private demo, because anyone who can reach the page can read the data, so the backend
**refuses to start** with `ALLOW_GUEST=true` unless `ENVIRONMENT` is `development` or `test`. Guest sessions are kept in the
backend's memory (they end when it restarts). See [docs/SECURITY.md](docs/SECURITY.md).

Static tokens from `AUTH_TOKENS` still work in accounts mode, for automation. In token mode, Settings has an *Access* card where a token can be entered for the browser tab (kept in `sessionStorage`, cleared when the tab closes); in accounts mode it shows the signed-in account and its session limits instead.

### Threat intelligence

Reputation lookups run in one of three modes. **The default is the offline mock; nothing leaves your machine unless you opt in.**

| Setting | Mode | Behaviour |
| --- | --- | --- |
| `THREAT_INTEL_PROVIDER=mock` (default) | `mock` | IOCs are looked up in the built-in **mock** dataset. Reputation `CLEAN` / `UNKNOWN` only means "the mock has no malicious record", **never "safe"**. |
| `THREAT_INTEL_PROVIDER=virustotal` **and** `VIRUSTOTAL_API_KEY` set | `live` | Public IPs, domains and file hashes are looked up on VirusTotal. |
| `THREAT_INTEL_PROVIDER=virustotal`, **no key** | `mock` (fallback) | Falls back to the mock **and says so**: the enrichment result carries `fallback_reason`, and Settings / `GET /config` show requested vs. active provider. |
| `THREAT_INTEL_MOCK_MODE=false` | `unavailable` | Overrides everything: IOCs are extracted but **not looked up**; every reputation is `UNKNOWN` ("not checked"). |

**Enabling VirusTotal.** Create a free account at virustotal.com, copy your API key, then put it in `backend/.env`
(never in the frontend, never in Git):

```
THREAT_INTEL_PROVIDER=virustotal
VIRUSTOTAL_API_KEY=<your key>
```

Restart the backend. Settings → *Analysis Configuration* shows the active provider, whether a key is configured (yes/no
only; the key is never returned or displayed) and the quota used.

**What is sent, and what is not.** Only the indicator value goes to `www.virustotal.com`, as a read-only lookup. Private,
loopback, link-local, reserved and other non-public IP addresses are **never** sent; neither are URLs (lookups are off
in this version), invalid or internal-looking domains (`.local`, `.internal`, file names such as `install.sh`), or
values that are not valid indicators. Indicators you do send are visible to VirusTotal: do not enable live mode for
data you may not disclose.

**Decoded command lines.** Indicators found inside base64 payloads of PowerShell command lines are **not sent** to VirusTotal
unless you set `VIRUSTOTAL_LOOKUP_DECODED_INDICATORS=true`. Without it they are reported as `not_sent_decoded_disabled`.
Turning it on sends values that were hidden inside encoded commands, so do so only if you accept that disclosure.

**Quota, honestly.** The public API allows **4 requests per minute and 500 per day** and may only be used for
**non-commercial** purposes (VirusTotal's terms). SOCMind AI never waits for quota inside a request. It spends at most
`VIRUSTOTAL_MAX_LOOKUPS_PER_ALERT` (default 5) requests per alert, answers repeats from an in-memory cache (24 h,
lost on restart), and stops sending while VirusTotal answers 429 or fails repeatedly. Indicators that could not be
checked are reported as `UNKNOWN` with a `lookup_status` such as `rate_limited`, the alert's enrichment is marked
`incomplete`, and the pipeline run is reported as **partial** with a warning. **Run the pipeline again a minute or
more later** and only the missing indicators are looked up. On the 10 sample alerts, 7 eligible indicators need at least
two minutes of quota.

**Reading live results.** `MALICIOUS` means at least `VIRUSTOTAL_MALICIOUS_THRESHOLD` (default 3) engines flagged it;
fewer flags (or any "suspicious") give `SUSPICIOUS`; zero flags give `CLEAN` with the note that this is not proof of
safety; "not found" gives `UNKNOWN`. Findings are attributed to VirusTotal, are never called "verified", and link to
the VirusTotal report. Detections can be false positives: the response agent still only **proposes** actions and a human
must approve them, and even an approved action is only simulated.

The sample alerts use real public addresses and well-known hashes, so live verdicts on them are not meaningful; use live
mode with real alert data, or treat the sample data as a demo of the workflow only.

## Database

Tables are created automatically at startup (`Base.metadata.create_all`). There is no migration framework; instead
`backend/app/db/session.py` runs one small, backward-compatible step: it adds the `incidents.details` column to an
older database if it is missing, and never deletes or rewrites existing rows (tested with an old-schema database).
It **cannot** rename or drop columns or change types; a real migration tool (for example Alembic) would be needed for
that. Delete `socmind.db` yourself if you want a clean start; the application and the tests never do.

## Tests

```bash
# Backend (from backend/)
python -m pytest

# Frontend (from frontend/)
npm test                    # unit tests for the pure helpers (node --test)
npm run build               # production build
npm run test:integration    # starts the real backend on a temporary database and drives the whole workflow
```

The backend tests always run on a **throw-away database in the system temp directory**: `tests/conftest.py` forces
`DATABASE_URL` before the app is imported, so your `socmind.db` and any `DATABASE_URL` in your shell or `.env` are never
opened (`tests/test_db_isolation.py` proves it). The integration test needs Python with `backend/requirements.txt`
installed (`PYTHON=python3 npm run test:integration` selects another interpreter).

`backend/tests/test_e2e_workflow.py` is the end-to-end workflow test: through the API only, one alert is ingested, triaged, enriched (mock intelligence), correlated into an incident, investigated, given recommendations, approved, simulated (nothing is executed) and closed, with an assertion at every step and an audit-log entry checked for each major action.

**Latest verification (2026-11-15, Windows, Python 3.14, Node 24; counts change as tests are added):**

| Command | Result |
| --- | --- |
| `python -m pytest -q` (backend) | **661 passed**, 0 failed |
| `npm test` (frontend unit tests) | **177 passed**, 0 failed |
| `npm run build` | succeeds |
| `npm run test:integration` | **149 checks passed** against a live backend on a temporary database |

Not covered: no browser was driven (the integration test renders pages server-side from live API data, so clicks, layout and styling are
unverified); the Docker images were never built or run (Docker is not installed here); PostgreSQL; and no linter or type checker is configured in this project.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'app'`**: start the backend from the `backend/` directory with
  `python -m uvicorn app.main:app`, not `python app/main.py`.
- **UI shows "Backend API: Unreachable"**: the backend is not running on port 8000, or `VITE_API_BASE` points elsewhere.
  Browsers also need your UI origin in `CORS_ORIGINS`.
- **"Load sample alerts" does nothing new**: the sample load is idempotent; the 10 sample alerts already exist.
- **Alerts show but there are no incidents**: run the pipeline (or "Correlate only"). At least two alerts must share a
  host, IP or file hash within the time window (default 24 h).
- **`401 Unauthorized`**: in token mode the request has no valid bearer token. Enter it in Settings → Access, or send
  `Authorization: Bearer <token>`. The message never shows the token. In accounts mode you are not signed in, the session
  ended (30 minutes without use, or 8 hours after sign-in), or the username or password is wrong
  (`Invalid username or password.`). Sign in again.
- **`403 Forbidden`**: the token is valid but its role is too low for the action (for example an analyst approving). Ask an
  approver, or use a token with the right role. In accounts mode, `403` can also mean a write request without the session's
  `X-CSRF-Token` header (the web page sends it for you).
- **`429` when signing in**: five failed sign-ins for one username and address lock that pair for 15 minutes, and the lock also
  refuses the correct password. Wait, then sign in again.
- **Cannot sign in because no account exists**: accounts mode starts with no accounts. Open the page and use *Create the first
  administrator account*, or from `backend/` run `python -m app.cli.accounts create-user --username NAME --role approver`. If
  accounts exist but every one is disabled, the first-run page is not offered (any account closes it); run
  `python -m app.cli.accounts enable-user --username NAME`.
- **Forgot a password**: an approver resets it under Settings → Users, or `python -m app.cli.accounts reset-password --username NAME`.
- **Backend refuses to start with "ALLOW_GUEST=true is refused ..."**: guest access is only allowed for `ENVIRONMENT=development`
  or `test`. Remove `ALLOW_GUEST` or set it to `false`.
- **Backend refuses to start with "AUTH_MODE is 'token' but ..."**: fix `AUTH_TOKENS` (at least one entry, a role of viewer,
  analyst or approver, and a token of 16 or more characters).
- **Backend refuses to start with "AUTH_MODE=disabled is refused ..."**: demo mode is only allowed for `ENVIRONMENT=development`
  or `test`. Set `AUTH_MODE=token` or `AUTH_MODE=accounts`.
- **Alert list shows "Showing N of M"**: only part of the list is loaded. Press *Load more*; the search still covers every alert.
- **`409` when approving or simulating**: a decision may already exist, the recommendations may be out of date because
  a new alert joined the incident (regenerate them first), or someone decided at the same moment. The message says which.
- **Pipeline `409 ... already in progress`**: another run is still going; wait and retry.
- **Windows: `npm run test:integration` cannot start the backend**: set `PYTHON` to the interpreter that has the backend
  requirements installed.

## Security limitations

The full model is in [docs/SECURITY.md](docs/SECURITY.md). In short:

- **Demo mode (`AUTH_MODE=disabled`, the default) has no authentication.** Anyone who can reach the API can approve,
  reject, simulate or run the pipeline. Run it only on a trusted local network.
- **Token mode is basic.** Tokens are static: no sign-in, no expiry, and revocation needs a restart. It has not been tested
  against a real identity provider, and traffic is not encrypted by the application (put HTTPS in front of it). Static tokens
  also work in accounts mode, for automation.
- **Accounts mode is a basic sign-in, not a full identity system.** Passwords are hashed with scrypt, sessions end after 30
  minutes without use and at most 8 hours after sign-in, five failed sign-ins lock a username and address pair for 15 minutes,
  and writes made with the cookie need a CSRF header. There is no password reset by e-mail (an approver resets a forgotten password), no
  multi-factor authentication and no self-service registration (an approver creates every account; the first-run page works only while
  no account exists, so whoever reaches an empty installation first creates its first administrator). The lockout does not stop an attack spread over many addresses, and the client address is the
  connection's address (`X-Forwarded-For` is not trusted). It needs HTTPS and the frontend and API on the same site
  (`SameSite=Strict`). It is covered by the automated tests; no browser was driven against it.
- Threat intelligence is mock data unless you enable VirusTotal; live verdicts are third-party opinions and can be wrong.
  The investigation logs are a bundled sample file.
- There is no real response integration; "simulated" means a record was written, nothing else.
- `CORS_ORIGINS` allows credentials; keep the list to origins you control.
- **Process-local state.** The pipeline run lock, the VirusTotal quota counters and the lookup cache live in one process.
  Several server workers would each have their own, so quotas and locks would not be shared. Run one worker process; the
  backend logs a warning when `WEB_CONCURRENCY` is above 1.
- **No database-level uniqueness for external alert IDs.** Duplicate upstream alerts are refused by an application check;
  only the internal alert ID is protected by the database. Adding a unique index needs a schema change.
- No general rate limiting on the API; the only limit is the sign-in lockout in accounts mode.
- The Docker files are written but **have not been built or run** (Docker was not available). See the Docker section.

## Roadmap

Not implemented yet (future work):

- Real SIEM, EDR and cloud connectors. Today alerts are synthetic or posted to the API, and investigation logs come from a sample file.
- Browser-level end-to-end tests. Today the integration test renders pages server-side from live API data; no browser is driven.
- A server-side alert status filter in the Alerts page. Today the status filter applies to the alerts already loaded (the API
  already accepts a `status` query parameter).
- Docker deployment verification. The Docker files are written, but no image has been built or run.

## Team contributions

From `git log --no-merges`, by commit author. Pull requests are merged by Chandresh Kumar. A commit author is the account that
made the commit, so this lists commits, not who wrote each line.

**Chandresh Kumar** (13 commits)

- Initial project import: FastAPI backend (alert API, correlation, investigation and response agents, mock threat-intelligence
  tool), React frontend and Docker files (`855d11f`, `a98b5ba`)
- Deterministic alert triage engine (`293d946`)
- Local IOC enrichment (`c03fdd2`) and triage and enrichment integration (`79d4bc0`)
- Multi-agent SOC pipeline (`8cbe524`) and workflow hardening (`824e5a7`)
- Optional live VirusTotal enrichment and stale-analysis handling, and the incident list search, filter and sort
  (`frontend/src/lib/incidentFilters.js`) (`5ba6f8a`, PR #2)
- Incident decision integrity and merged state (`2e817b0`); response target validation (`e80bddc`)
- Token authentication with roles, `docs/SECURITY.md` and security hardening (`576fcc5`)
- Audit log export to CSV (`5569142`)
- Alert status filter, close action and end-to-end workflow test (`71b5afc`, PR #5)

**Kalpna Chaudhary** (2 commits)

- Login and logout authentication (`9c3a1df`, PR #4): accounts mode with username and password sign-in, scrypt password hashing,
  session cookies with CSRF protection and sign-in lockout, a command line to create accounts, the Login page and tests
- Login improvements (branch `kalpna/login-improvements`): account management by an approver (create, disable, enable), change
  password, a session expiry warning, the Authentication events audit filter, the Compose settings for accounts mode,
  first-run setup of the first administrator, password reset by an approver, and an optional read-only guest

## Project team

- **Team**: 150 · **Team Leader**: Chandresh Kumar · **Team Member**: Kalpna Chaudhary · **Mentor**: Sachin Kumar Yadav
