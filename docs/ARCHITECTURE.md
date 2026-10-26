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
  dataset**. See "Threat-intelligence modes" below.
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
new correlated alerts change the incident afterwards, the decision is voided, the status returns to `OPEN` /
`PENDING`, the old decision and any simulation are kept in `details.review_history`, and an `APPROVAL_RESET` audit
entry is written.

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

| `intel_mode` | When | What it means |
| --- | --- | --- |
| `mock` | `THREAT_INTEL_MOCK_MODE=true` (default) | IOCs are looked up in a small **local mock dataset** (`tools/mock_intel.py`). Not live, not verified. `CLEAN` / `UNKNOWN` only mean "the mock has no malicious record". |
| `unavailable` | `THREAT_INTEL_MOCK_MODE=false` | IOCs are extracted but **not looked up**. Every reputation is `UNKNOWN` with `lookup_performed: false`; it means "not checked". |

There is **no live provider** (VirusTotal, AbuseIPDB and so on); none is implemented, and the project's safety rules
forbid real credentials. Every enrichment result carries `verified: false`, `intel_mode` and a `disclaimer`.

## Time handling

Everything is stored and compared as UTC. Alerts with an offset (`+05:30`) are converted on ingest. API responses
render timestamps as ISO-8601 with a `Z` suffix. The UI labels times "UTC".

## Frontend

React 18 + Vite. `src/api.js` is the only place that calls the backend; it turns HTTP errors into readable messages.
Pages: Dashboard, Security Alerts, Correlated Incidents, Agent Pipeline, Audit Log, Settings (read-only view of
`GET /config`). Pure helpers live in `src/lib/view.js` (unit tested); `src/lib/useAsync.js` provides loading / error /
data state. Every list has loading, error and empty states. Sample data is only loaded when the analyst presses
"Load sample (synthetic) alerts".
