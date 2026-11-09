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
| Authentication | **None.** See "Security limitations". |

> **Safety boundaries.** All data is synthetic, public or explicitly authorized test data. No real credentials or
> enterprise connections. Command-line strings in alerts are treated strictly as data and never executed. Every
> recommendation requires an explicit human decision, and even an approved one is only simulated.

## Architecture

```
React UI (Vite, :5173) ──HTTP──► FastAPI (:8000) ──► SQLite (alerts, incidents, audit_logs)
                                    │
                    Triage ─► Enrichment ─► Correlation ─► Investigation ─► Response ─► [human approves/rejects] ─► [simulation]
```

Details of every stage, the state machines, concurrency guards and the audit trail: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.
Endpoint reference with examples: **[docs/API.md](docs/API.md)**.

```
backend/app/
  api/v1/        routers: alerts, incidents, pipeline + agents, audit-logs, stats/config, health
  agents/        triage, enrichment, correlation, investigation, response
  services/      orchestrator, incident_service, pipeline_steps, normalization, audit, seed, log_store
  tools/         mock_intel.py (offline mock intelligence), virustotal.py (opt-in VirusTotal client)
  models/        SQLAlchemy models        schemas/   Pydantic request/response models
  db/session.py  engine, sessions, and the small startup schema upgrade
backend/tests/   pytest suite (178 tests)
frontend/src/    React app (api.js, pages/, components/, lib/)
frontend/scripts/integration-smoke.mjs   frontend <-> backend integration test
data/            synthetic alerts and logs
docs/            ARCHITECTURE.md, API.md, KALPNA_FEATURE_RESERVATION.md
```

## Prerequisites

- Python 3.11 or newer (developed and tested with 3.14) and `pip`
- Node.js 18 or newer (tested with 24) and `npm`
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

1. *Security Alerts* → **Load sample (synthetic) alerts** (nothing is loaded automatically).
2. Open an alert → **Run triage**, **Run enrichment**.
3. *Agent Pipeline* → **Run full pipeline**. Sample data produces 2 incidents.
4. *Correlated Incidents* → expand an incident: why the alerts were grouped, the timeline, verified facts vs mock
   intelligence vs hypotheses, and the proposed actions (each marked NOT EXECUTED).
5. Enter your name → **Approve** or **Reject**; after approving, optionally **Run simulation (no real action)**.
6. *Audit Log* shows who did what; *Settings* shows the backend's real configuration (read-only).

Or from the command line: `curl -X POST localhost:8000/api/v1/alerts/seed` then `curl -X POST localhost:8000/api/v1/pipeline/run`.

### Docker (provided, unverified)

`docker compose up --build` is configured (`docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`; the frontend
image runs the Vite dev server). It was **not** run during the latest verification, so treat it as untested.

## Configuration

Copy [`.env.example`](.env.example) to `backend/.env`. Every variable is optional. Only variables the code reads are listed:
`PROJECT_NAME`, `ENVIRONMENT`, `DEBUG`, `LOG_LEVEL`, `DATABASE_URL`, `CORS_ORIGINS`, `THREAT_INTEL_MOCK_MODE`,
`THREAT_INTEL_PROVIDER` and the `VIRUSTOTAL_*` settings described below. Never commit a real `.env` (it is in `.gitignore`).

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

**Latest verification (2026-10-22, Windows, Python 3.14.4, Node 24.15.0):**

| Command | Result |
| --- | --- |
| `python -m pytest` (backend) | **178 passed**, 0 failed (includes the 44 enrichment tests, unchanged) |
| `npm test` (frontend) | **11 passed**, 0 failed |
| `npm run build` | succeeds |
| `npm run test:integration` | **39 checks passed** against a live backend |

Not covered: no browser was driven (the integration test renders pages server-side from live API data, so clicks,
layout and styling are unverified); Docker; PostgreSQL; and no linter or type checker is configured in this project.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'app'`**: start the backend from the `backend/` directory with
  `python -m uvicorn app.main:app`, not `python app/main.py`.
- **UI shows "Backend API: Unreachable"**: the backend is not running on port 8000, or `VITE_API_BASE` points elsewhere.
  Browsers also need your UI origin in `CORS_ORIGINS`.
- **"Load sample alerts" does nothing new**: the sample load is idempotent; the 10 sample alerts already exist.
- **Alerts show but there are no incidents**: run the pipeline (or "Correlate only"). At least two alerts must share a
  host, IP or file hash within the time window (default 24 h).
- **`409` when approving or simulating**: a decision may already exist, the recommendations may be out of date because
  a new alert joined the incident (regenerate them first), or someone decided at the same moment. The message says which.
- **Pipeline `409 ... already in progress`**: another run is still going; wait and retry.
- **Windows: `npm run test:integration` cannot start the backend**: set `PYTHON` to the interpreter that has the backend
  requirements installed.

## Security limitations

- **No authentication or authorization.** Anyone who can reach the API can approve, reject, simulate or run the pipeline.
  Reviewer names are self-asserted free text. Run it only on a trusted local network and do not expose it publicly.
- Adding authentication was deliberately left out of scope; the approval workflow would need real identities first.
- Threat intelligence is mock data unless you enable VirusTotal; live verdicts are third-party opinions and can be wrong. Investigation logs are a bundled sample file.
- There is no real response integration; "simulated" means a record was written, nothing else.
- `CORS_ORIGINS` allows credentials; keep the list to origins you control.
- The pipeline run lock is per process (several server workers would not share it).
- Input length limits exist, but there is no rate limiting.

## Roadmap

A reserved, independent feature (incident list search, filtering and sorting) is specified in
[docs/KALPNA_FEATURE_RESERVATION.md](docs/KALPNA_FEATURE_RESERVATION.md). It is **not implemented yet**.

## Project team

- **Team**: 150 · **Team Leader**: Chandresh Kumar · **Team Member**: Kalpna Chaudhary · **Mentor**: Sachin Kumar Yadav
