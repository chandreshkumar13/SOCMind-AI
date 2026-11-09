# SOCMind AI architecture

## Overview

```
   Browser (React + Vite, port 5173)
        │  fetch  (frontend/src/api.js, base URL http://localhost:8000/api/v1)
        ▼
   FastAPI app (backend/app/main.py)  ── routers in backend/app/api/v1/
        │
        ├── services/   business logic shared by routes and the orchestrator
        ├── agents/     five deterministic, rule-based agents (no LLM is called)
        └── SQLAlchemy ─► SQLite file (default) or any SQLAlchemy URL
                          tables: alerts, incidents, audit_logs
```

All five agents are plain Python rules. `LLM_PROVIDER` exists in the settings but nothing reads it; the Settings page
and `GET /api/v1/config` say so explicitly.

## The pipeline

`POST /api/v1/pipeline/run` (`backend/app/services/orchestrator.py`) runs five stages in order on the alerts stored in
the database. Each stage reads what the previous stage persisted; nothing is passed through hidden state.

| # | Stage | Reads | Writes | Skips work when |
| - | --- | --- | --- | --- |
| 1 | **Triage Agent** | alert fields | `alert.normalized_data.triage` (score 0-100, priority, indicators, rationale); status `TRIAGED` | the alert already has a triage result |
| 2 | **Enrichment Agent** | alert fields, free text | `alert.normalized_data.enrichment` (IOCs with reputation); status `ENRICHED` | the alert already has an enrichment result |
| 3 | **Correlation Agent** | all non-closed alerts | `incidents` rows, `alert.normalized_data.incident_id`; alert status `CORRELATED` | the group already matches an incident (reported as `unchanged`) |
| 4 | **Investigation Agent** | incident alerts, triage, enrichment, correlation record, sample logs | `incident.details.investigation`, `incident.ai_summary`; alert status `INVESTIGATING` | the investigation exists and is not stale |
| 5 | **Response Agent** | incident alerts, investigation | `incident.details.recommendations`, `incident.recommended_action`; status `RESPONSE_PROPOSED` | a human decision exists, or recommendations are fresh |

Approval is deliberately **not** a pipeline stage. It is a separate human action.

Properties of a run:

- **Idempotent.** Running twice without new data creates and changes nothing (every stage reports `processed: 0`).
- **Failure isolated.** An exception in one item or stage is recorded (`errors`, audit action `AGENT_FAILED`) and later
  stages still run.
- **Recoverable.** Work that failed is not marked done, so the next run retries it (for example alerts whose
  enrichment failed).
- **Honest outcome.** `outcome` is `success`, `partial` (something failed but other work succeeded) or `failure`
  (every stage that tried to do work failed). The HTTP status stays 200 for a completed run; read `outcome`.
- **One at a time.** A second concurrent run gets HTTP 409. The lock is per process.
- **Scoped.** `alert_ids` limits triage and enrichment. Correlation always considers every non-closed alert, because an
  incident can only be recognised against all open alerts.
- **Audited.** Every run writes a `PIPELINE_RUN` audit entry containing the full stage report.

### Agent details

- **Triage** (`agents/triage/triage_agent.py`): base score from severity plus points for indicators (entities present,
  encoded or credential-dumping command patterns, threat keywords, privileged user). Command lines are only read as
  text. Deterministic: the same alert always scores the same.
- **Enrichment** (`agents/enrichment/enrichment_agent.py`, `tools/mock_intel.py`): extracts IPv4/IPv6, SHA256/SHA1/MD5,
  URLs and domains from structured fields and free text, de-duplicates them, and looks each up in a **local mock
  dataset** by default, or on VirusTotal when live mode is enabled. See "Threat-intelligence modes" below.
- **Correlation** (`agents/correlation/correlation_agent.py`): two alerts are linked when they share a host, source IP,
  destination IP or file hash **and** are within the time window (default 24 h, 1-168). Linking is transitive. A shared
  username never links alerts by itself. Timestamps are compared in UTC. Alerts that are `CLOSED`, have no id, or have no valid timestamp are never linked;
  alerts with a missing or malformed timestamp are listed in the run warnings. A group needs at least two alerts.
- **Investigation** (`agents/investigation/investigation_agent.py`): builds a UTC timeline from alerts and log records,
  and labels every finding `verified` (present in a stored alert, triage result, correlation record or log),
  `mock_intel` (flagged by the mock lookup; always marked unverified) or `hypothesis` (keyword rule mapped to a MITRE
  ATT&CK technique id; confidence is never above `medium`). It lists `limitations` (no logs matched, alerts not
  enriched, and so on) instead of guessing. Logs come from `data/sample_logs/sample_logs.json`; no SIEM is queried and
  the result says so (`log_source`).
- **Response** (`agents/response/response_agent.py`): proposes actions only. Each recommendation has category,
  justification, expected benefit, operational impact, risk if wrong, required approvals, preconditions, validation
  steps, rollback, supporting evidence and related techniques. Weak evidence yields only "collect additional
  evidence". Every recommendation has `requires_approval: true`, `executed: false`.

## State machines

**Alert status**: `NEW → TRIAGED → ENRICHED → CORRELATED → INVESTIGATING`, and `CLOSED` (set by
`DELETE /alerts/{id}`). A step only moves an alert forward from the statuses it is allowed to start from, and
**`CLOSED` is never changed** by triage, enrichment, correlation or investigation.

**Incident status**: `OPEN → INVESTIGATED → RESPONSE_PROPOSED → RESPONSE_APPROVED | RESPONSE_REJECTED →
RESPONSE_SIMULATED` (simulation is only reachable from `RESPONSE_APPROVED`). `MERGED` marks an incident absorbed by
another when correlation finds that two incidents belong together.

**Approval** (`human_approval_status`): `PENDING → APPROVED | REJECTED`. A decision is final, with one exception: if
the evidence under it changes afterwards, the decision is withdrawn, the status returns to `OPEN` / `PENDING`, the old
decision and any simulation are kept in `details.review_history` (with `superseded_by`), and an `APPROVAL_RESET` audit
entry is written. Two things trigger this: new correlated alerts, and a material change to an alert's threat-intelligence
result (see below). Withdrawing a decision is never an execution; it only means a person must review the new recommendations.

### Staleness of derived analysis (`services/staleness.py`)

An incident's investigation and recommendations are computed from its alerts' triage and enrichment. When an alert's
enrichment is recorded, `enrich_alert_record` compares it with the previous result using a fingerprint: the intel mode and
provider, whether lookups are incomplete, the extracted indicators, and the verdict and evidence of every flagged indicator.
Timestamps, retrieval times, cache hits and lookup counters are ignored, so a re-run that returns the same verdicts changes
nothing. Reputations of unflagged indicators are ignored too, because the analysis never quotes them.

When the fingerprint changes, every open incident that contains the alert and already has analysis gets:
`investigation_stale` and `recommendations_stale` set to `true`, a `stale_reasons` entry (for example
`threat-intelligence source changed: mock -> live (VirusTotal)`), an `INCIDENT_STALE` audit entry, and (if a decision was
recorded) a withdrawn decision as above. The next pipeline run, or a direct re-investigation, recomputes the findings from the
latest stored enrichment; the next recommendation run clears the reasons. Incidents with no analysis yet are not marked, and
merged incidents are never touched. The pipeline runs enrichment before investigation, so a change made during a run is
picked up in the same run.

Marking at change time is not the only safeguard. Each investigation stores `analysis_basis`: a digest of every alert's
enrichment as it was when the analysis ran. Before investigating, each pipeline run compares those digests with the current
data (`reconcile_incidents_with_evidence`) and marks any fresh incident that no longer matches. This also refreshes analysis
built before this tracking existed (reason: "analysis was built before change tracking"). Such incidents are refreshed once,
and a decision recorded on them is withdrawn once, because the approved advice may rest on outdated intelligence; a person
must then review it again. Withdrawals and refreshes are always audited, and nothing is executed.

### Approved is not executed

There is **no real response integration**. "Approved" means a named human agreed to the proposal. The only further
step is a **simulation** (`POST /incidents/{id}/simulate`): it records, per action, that the workflow was rehearsed
and that "no command was run and no system was changed". Every recommendation keeps `executed: false`, and there is
no `EXECUTED` state anywhere. `EXECUTION_MODE = "simulation_only"` is a constant in `backend/app/core/config.py`, not
a setting, because there is nothing a configuration value could safely switch on.

### Concurrency guards

Approve / reject / simulate claim their state change with a conditional `UPDATE ... WHERE human_approval_status =
'PENDING'` (or `status = 'RESPONSE_APPROVED'`). Of two simultaneous requests only one matches a row; the other gets
HTTP 409. Incident creation retries once if two requests pick the same new incident id.

## Audit trail

Every significant action writes a row to `audit_logs` in the **same transaction** as the change it describes, so they
succeed or fail together. A request that is refused (409, 422, 404) writes nothing. Entries record actor (an agent
name, `API`, or the reviewer's name), action, target id, UTC time and a JSON details object. Actions include
`ALERT_INGESTED`, `ALERT_TRIAGED`, `ALERT_ENRICHED`, `ALERT_CLOSED`, `ALERTS_SEEDED`, `INCIDENT_CREATED`,
`INCIDENT_UPDATED`, `INCIDENT_MERGED`, `INCIDENT_INVESTIGATED`, `RESPONSE_RECOMMENDED`, `INCIDENT_APPROVED`,
`INCIDENT_REJECTED`, `RESPONSE_SIMULATED`, `APPROVAL_RESET`, `AGENT_FAILED`, `PIPELINE_RUN`. Secrets are never
written; error details are truncated to 300 characters and contain no stack traces.

## Threat-intelligence modes

`services/threat_intel.py::resolve_provider()` picks the source for every enrichment, in this order:

1. `THREAT_INTEL_MOCK_MODE=false` → **`unavailable`**: IOCs are extracted, nothing is looked up.
2. `THREAT_INTEL_PROVIDER=virustotal` and a non-empty `VIRUSTOTAL_API_KEY` → **`virustotal`** (live, opt-in).
3. `THREAT_INTEL_PROVIDER=virustotal` without a key, or an unknown provider name → **`mock`** with a `fallback_reason`.
4. Otherwise (the default) → **`mock`**.

| `intel_mode` | Source | What it means |
| --- | --- | --- |
| `mock` | `tools/mock_intel.py` | A small local dataset. Not live, not verified. `CLEAN` / `UNKNOWN` only mean "the mock has no malicious record". |
| `live` | VirusTotal public API v3 | Third-party engine verdicts, attributed to VirusTotal and **not independently verified**. |
| `unavailable` | none | `lookup_performed: false`; every reputation is `UNKNOWN` = "not checked". |

Every enrichment result carries `verified: false`, `intel_mode` and a `disclaimer`. Live results add `provider`,
`lookup_summary`, `incomplete` and, per indicator, `lookup_status`, `detections`, `detected_by`, `retrieved_at`,
`reference_url` and `cached`. The original contract (`total_iocs_extracted`, `summary`, `iocs[]` with `type`, `value`,
`source`, `reputation`, `confidence`, `evidence`, `provider`) is unchanged.

### How a live lookup works (`tools/virustotal.py`, `agents/enrichment/live_enrichment_agent.py`)

`LiveEnrichmentAgent` subclasses the existing `EnrichmentAgent` and overrides only the lookup, so extraction,
de-duplication and the result shape are shared with the mock path. For each extracted indicator:

1. **Eligibility.** Only public IPs (not private, loopback, link-local, multicast, reserved, documentation or CGNAT
   ranges), file hashes (MD5/SHA-1/SHA-256) and plausible public domains are sent. URLs are never sent. Values are
   validated per type and percent-encoded; the VirusTotal base URL is a constant, so alert text can never redirect a
   request. Ineligible indicators get `lookup_status: skipped_*` and cost nothing.
2. **Cache.** Completed lookups (24 h) and "not found" answers (1 h) are served from memory at no cost.
3. **Budget.** At most `VIRUSTOTAL_MAX_LOOKUPS_PER_ALERT` requests per alert, within a sliding window of
   `VIRUSTOTAL_REQUESTS_PER_MINUTE` / `VIRUSTOTAL_REQUESTS_PER_DAY`. When the budget is gone the indicator is reported as
   `budget_exceeded` / `rate_limited`. **The code never sleeps to wait for quota.**
4. **Request.** One `GET` with the key in the `x-apikey` header, a connect/read timeout, no redirects and no retries.
5. **Answer mapping.** 200 → verdict from `last_analysis_stats`; 404 → `UNKNOWN` (`not_found`); 401/403 → `auth_error`
   (lookups stop until the app is restarted with a working key); 429 → `rate_limited` and **all** requests pause for
   `Retry-After` (default 60 s; until 00:00 UTC for a daily-quota error); timeouts, 5xx, unusable JSON → `timeout` /
   `error`. After three consecutive failures lookups pause for 60 s (`circuit_open`).

Only a small summary is stored (counts, up to five detecting engine names, the report link), never the raw response.

### Partial enrichment and retries

`incomplete` is true when any indicator ended in a *retryable* status (`rate_limited`, `budget_exceeded`, `timeout`,
`error`, `circuit_open`). The orchestrator then (a) marks the Enrichment stage `partial` with a note and a run warning,
which makes the run's `outcome` **partial** (a quota is not an error, but the work is not finished), and (b) re-enriches
that alert on the next run; completed indicators come from the cache, so a later run only spends quota on what is
missing. Permanent outcomes (`not_found`, `auth_error`, `skipped_*`) are not retried. Because the cache is in memory, a
restart forgets it, so a restart can cost quota again.

### Secrets

`VIRUSTOTAL_API_KEY` is a `SecretStr`. It exists only in the request header: it is not in any URL, result, audit entry,
API response (`GET /config` returns only `api_key_configured: true/false`), exception text or log line. Failures are
reported with fixed status texts, never with raw server or library messages, and the `httpx` request log is silenced so
indicator values and provider URLs do not reach the application log. Tests assert all of this, including against a fake
server that echoes the key back in its error bodies.

### What this does not do

It reads reports. It never submits files or URLs for scanning, and nothing here blocks, quarantines or changes
anything: recommendations that mention a live verdict are still proposals that need a human decision, and an approved
response is only simulated.

## Time handling

Everything is stored and compared as UTC. Alerts with an offset (`+05:30`) are converted on ingest. API responses
render timestamps as ISO-8601 with a `Z` suffix. The UI labels times "UTC".

## Frontend

React 18 + Vite. `src/api.js` is the only place that calls the backend; it turns HTTP errors into readable messages.
Pages: Dashboard, Security Alerts, Correlated Incidents, Agent Pipeline, Audit Log, Settings (read-only view of
`GET /config`). Pure helpers live in `src/lib/view.js` (unit tested); `src/lib/useAsync.js` provides loading / error /
data state. Every list has loading, error and empty states. Sample data is only loaded when the analyst presses
"Load sample (synthetic) alerts".
