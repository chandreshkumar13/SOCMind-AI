# SOCMind AI API reference

Base URL: `http://localhost:8000/api/v1`. Interactive documentation generated from the code is always available at
`http://localhost:8000/docs` (Swagger UI) and `/redoc`; this file adds the behaviour and examples.

- All bodies are JSON. All timestamps are UTC, rendered like `2026-09-03T08:14:00Z`.
- There is **no authentication**. Reviewer / actor names are free text supplied by the caller. Do not expose the API
  to an untrusted network.
- Errors: `{"detail": "..."}` for 404 / 409 / 422 / 502. Unexpected server errors return HTTP 500 with a generic
  message; the details are in the server log only.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness, environment, database **engine** (never the connection string) |
| GET | `/version` | Version and runtime information |
| GET | `/config` | Non-secret runtime configuration (threat-intel mode, execution mode, authentication status) |
| GET | `/stats` | True totals computed in the database (alerts by severity/status, incidents, awaiting review, audit count) |
| POST | `/alerts` | Ingest and normalize one alert |
| GET | `/alerts` | List alerts. Query: `severity`, `status`, `source`, `search`, `limit` (1-100, default 50), `offset` |
| GET | `/alerts/{id}` | One alert, including `normalized_data.triage` / `.enrichment` / `.incident_id` |
| DELETE | `/alerts/{id}` | Close an alert (status `CLOSED`; the record is kept) |
| POST | `/alerts/seed` | Load the 10 synthetic sample alerts (idempotent) |
| POST | `/alerts/{id}/triage` | Run deterministic triage on one alert |
| POST | `/alerts/{id}/enrich` | Extract IOCs and look them up (local mock by default, VirusTotal when enabled) |
| POST | `/incidents/correlate` | Group related open alerts into incidents. Body: `{"window_hours": 1-168}` (default 24) |
| GET | `/incidents` | List incidents. Query: `severity`, `status`, `approval`, `limit` (1-100, default 50), `offset` |
| GET | `/incidents/{id}` | One incident with its alerts, investigation, recommendations, review and simulation |
| POST | `/incidents/{id}/investigate` | (Re)run the investigation |
| POST | `/incidents/{id}/recommend` | (Re)generate recommendations; refused once a decision exists |
| POST | `/incidents/{id}/approve` | Record a human approval (nothing is executed) |
| POST | `/incidents/{id}/reject` | Record a human rejection |
| POST | `/incidents/{id}/simulate` | Rehearse an approved response (nothing is executed) |
| POST | `/pipeline/run` | Run Triage → Enrichment → Correlation → Investigation → Response |
| GET | `/pipeline/runs` | Recent run reports (`limit` 1-50, default 10) |
| GET | `/agents` | Per-agent activity derived from the audit log |
| GET | `/audit-logs` | Audit entries, newest first. Query: `actor`, `action`, `target_id`, `limit` (1-200, default 50), `offset` |

## Alerts

### Ingest

Accepts raw or semi-structured fields and normalizes them (severity words and numbers, source system names, entity
field aliases, timestamps). Unknown extra fields are accepted and ignored. Text fields have length limits
(title 500, description and command line 10 000, host / user / source 255, id 100); longer values return 422.

```bash
curl -X POST http://localhost:8000/api/v1/alerts -H "Content-Type: application/json" -d '{
  "alert_title": "Suspicious PowerShell",
  "source": "CrowdStrike EDR",
  "severity": "high",
  "host": "WKS-017",
  "username": "j.doe",
  "destination_ip": "185.220.101.5",
  "timestamp": "2026-09-03T13:44:00+05:30",
  "external_alert_id": "CS-90412"
}'
```

Returns `201` with the stored alert. The timestamp above is stored and returned as `2026-09-03T08:14:00Z`.

| Status | Meaning |
| --- | --- |
| 201 | Stored |
| 409 | An alert with that `id` already exists, **or** the same source system already sent that `external_alert_id` (the response names the existing alert) |
| 422 | Validation failed (for example a field is too long) |

### Triage and enrichment

`POST /alerts/{id}/triage` returns `{"alert": {...}, "triage_result": {"suspicion_score": 0-100, "priority": "...", "indicators": [...], "rationale": "..."}}`.

`POST /alerts/{id}/enrich` returns `{"alert": {...}, "enrichment_result": {...}}`:

```json
{
  "agent": "Enrichment Agent", "status": "completed", "alert_id": "ALT-2026-001",
  "total_iocs_extracted": 3,
  "summary": {"malicious": 1, "suspicious": 0, "clean": 1, "unknown": 1},
  "iocs": [{"value": "185.220.101.5", "type": "IP", "source": "destination_ip",
            "reputation": "MALICIOUS", "confidence": 0.95, "evidence": "...", "provider": "MockThreatIntel"}],
  "intel_mode": "mock", "verified": false, "disclaimer": "Results come from LOCAL MOCK threat intelligence ..."
}
```

IOC `type` is `IP`, `SHA256`, `SHA1`, `MD5`, `DOMAIN` or `URL`; `reputation` is `MALICIOUS`, `SUSPICIOUS`, `CLEAN` or
`UNKNOWN`. **`CLEAN` / `UNKNOWN` never mean verified safe.**

`intel_mode` says where the reputations came from:

- `"mock"` (default): the local sample dataset. If `THREAT_INTEL_PROVIDER=virustotal` was set without an API key, the
  result is still `"mock"` and also carries `requested_provider` and `fallback_reason`.
- `"unavailable"` (`THREAT_INTEL_MOCK_MODE=false`): `lookup_performed` is `false` and every reputation is `UNKNOWN`
  ("not checked").
- `"live"` (`THREAT_INTEL_PROVIDER=virustotal` with a key): VirusTotal verdicts. Additional keys, all optional for
  clients: `provider`, `incomplete`, `lookup_performed`, `lookup_summary`
  (`requests_made`, `completed`, `from_cache`, `skipped_ineligible`, `not_looked_up_retryable`, `rate_limited`,
  `per_alert_limit_reached`, `failed`, `auth_error`) and, per IOC, `lookup_status`, `detections`
  (`malicious`, `suspicious`, `harmless`, `undetected`, `total`), `detected_by`, `retrieved_at`, `reference_url`, `cached`.

```json
{
  "intel_mode": "live", "provider": "VirusTotal", "verified": false, "incomplete": true,
  "lookup_summary": {"requests_made": 4, "completed": 4, "from_cache": 0, "skipped_ineligible": 3, "not_looked_up_retryable": 2,
                     "rate_limited": 2, "per_alert_limit_reached": 0, "failed": 0, "auth_error": 0},
  "iocs": [
    {"value": "185.220.101.5", "type": "IP", "source": "destination_ip", "reputation": "MALICIOUS", "confidence": 0.17,
     "provider": "VirusTotal", "lookup_status": "completed", "cached": false,
     "evidence": "12 of 70 engines flagged it as malicious (VirusTotal, analysed 2026-10-24).",
     "detections": {"malicious": 12, "suspicious": 0, "harmless": 50, "undetected": 8, "total": 70}, "detected_by": ["EngineA"],
     "retrieved_at": "2026-10-26T09:00:00Z", "reference_url": "https://www.virustotal.com/gui/ip-address/185.220.101.5"},
    {"value": "10.0.0.5", "type": "IP", "reputation": "UNKNOWN", "provider": "none", "lookup_status": "skipped_non_public_ip"},
    {"value": "8.8.8.8", "type": "IP", "reputation": "UNKNOWN", "provider": "none", "lookup_status": "rate_limited"}
  ]
}
```

`lookup_status` is one of `completed`, `not_found`, `rate_limited`, `budget_exceeded`, `timeout`, `error`, `circuit_open`,
`auth_error`, `skipped_non_public_ip`, `skipped_invalid`, `skipped_url`, `skipped_unsupported`. `rate_limited`,
`budget_exceeded`, `timeout`, `error` and `circuit_open` are **retryable** (they set `incomplete: true`): enrich again
later to finish them. The others are final for that indicator. A quota or provider problem is not an HTTP error: the response is still `200`. A reputation of `UNKNOWN` with a
`skipped_*` or retryable status means "not checked", never "safe".

Both steps leave a `CLOSED` alert closed. If the agent fails, the response is `502`, the alert is **not modified**, and
an `AGENT_FAILED` audit entry is written. A missing alert returns `404`.

## Incidents

```bash
curl -X POST http://localhost:8000/api/v1/incidents/correlate -H "Content-Type: application/json" -d '{"window_hours": 24}'
```

Returns `{"alerts_considered", "groups_found", "created": [ids], "updated": [ids], "unchanged": [ids], "alerts_without_valid_timestamp": [ids], "message"}`.
Running it again returns the same incidents under `unchanged`. `window_hours` outside 1-168 returns `422`.

An incident (`GET /incidents/{id}`) has:

| Field | Content |
| --- | --- |
| `severity` | The highest severity among its alerts |
| `status` | `OPEN`, `INVESTIGATED`, `RESPONSE_PROPOSED`, `RESPONSE_APPROVED`, `RESPONSE_REJECTED`, `RESPONSE_SIMULATED`, `MERGED` |
| `human_approval_status` | `PENDING`, `APPROVED`, `REJECTED` |
| `alerts` | The full correlated alert records |
| `details.correlation` | Why the alerts were grouped (`reasons`, `shared_entities`, `confidence`, `first_seen`, `last_seen`, `window_hours`) |
| `details.investigation` | `summary`, `evidence_strength`, `timeline`, `findings` (`verified` / `mock_intel` / `external_intel` / `hypothesis`; `external_intel` is a live VirusTotal verdict, attributed and unverified), `entities`, `limitations`, `log_source` |
| `details.recommendations` | The proposed actions (fields below) |
| `details.review` / `details.simulation` | The current decision and simulation, when present |
| `details.review_history` | Earlier decisions withdrawn because the evidence changed (each with `superseded_by`) |
| `details.investigation_stale`, `details.recommendations_stale` | `true` when new correlated alerts, or a material change to an alert's threat-intelligence result, came after that step ran |
| `details.stale_reasons` | Why the analysis is out of date: `[{alert_id, change, at}]`, newest last (at most 20; `alert_id` is `null` for changes not tied to one alert). Cleared when recommendations are regenerated |
| `details.analysis_basis` | Digest of each alert's enrichment that the investigation was built from. Compared with the current data before each pipeline run |

A recommendation has: `id`, `category`, `priority`, `action`, `target`, `justification`, `supporting_evidence`,
`related_techniques`, `expected_benefit`, `impact`, `operational_impact`, `risk_if_wrong`, `reversible`, `rollback`,
`required_approvals`, `preconditions`, `validation_steps`, `requires_approval` (always `true`), `status`
(`PENDING` / `APPROVED` / `REJECTED`), `executed` (**always `false`**) and `simulation_status` (`NOT_RUN` / `SIMULATED`).

### Decisions

```bash
curl -X POST http://localhost:8000/api/v1/incidents/INC-2026-001/approve -H "Content-Type: application/json" \
     -d '{"reviewer": "Chandresh Kumar", "reason": "Confirmed with log evidence"}'
curl -X POST http://localhost:8000/api/v1/incidents/INC-2026-001/simulate -H "Content-Type: application/json" \
     -d '{"reviewer": "Chandresh Kumar"}'
```

`reviewer` is required (1-100 characters); `reason` is optional (up to 500).

| Call | Succeeds when | 409 when |
| --- | --- | --- |
| `recommend` | no human decision exists yet | a decision is already recorded |
| `approve` / `reject` | recommendations exist, are current, and no decision exists | none exist, they are out of date, or a decision exists (including one made at the same moment by someone else) |
| `simulate` | the decision is `APPROVED`, current, and not yet simulated | any other state, or already simulated |

Unknown incident ids return `404`; a missing or empty `reviewer` returns `422`. **Approving does not execute anything,
and neither does simulating**: the simulation only records, per action, that nothing was run.

## Pipeline

```bash
curl -X POST http://localhost:8000/api/v1/pipeline/run -H "Content-Type: application/json" \
     -d '{"alert_ids": ["ALT-2026-001"], "window_hours": 24}'     # body is optional
```

Response (abridged):

```json
{
  "run_id": "59d46aa28cb9", "status": "completed", "outcome": "success", "duration_ms": 308,
  "alerts_in_scope": 10, "unknown_alert_ids": [], "closed_alert_ids": [], "warnings": [],
  "stages": [
    {"agent": "Triage Agent", "status": "success", "processed": 10, "items": ["ALT-2026-001", "..."],
     "skipped": 0, "duration_ms": 103, "errors": [], "notes": []}
  ],
  "incidents_created": ["INC-2026-001", "INC-2026-002"], "incidents_updated": [], "incidents_unchanged": [],
  "incidents_awaiting_human_review": 2,
  "message": "Incidents created/updated from correlated alerts."
}
```

- `alerts_with_incomplete_enrichment`: how many alerts still have retryable live lookups. When it is above zero the
  Enrichment stage is `partial`, a warning explains why, and the run's `outcome` is `partial`; running the pipeline again
  later completes the missing lookups.
- `outcome`: `success`, `partial` (some stage failed or partly failed; `status` is `completed_with_errors`) or
  `failure` (every stage that tried to work failed; `status` is `failed`). The HTTP status is still 200.
- A stage `status` is `success`, `partial` or `failed`. `items` lists up to 50 ids the stage handled; `processed` is the
  true count.
- `404` if `alert_ids` is given and none exist; `409` if a run is already in progress; `422` for a bad `window_hours`.
  Unknown ids among valid ones are reported in `unknown_alert_ids` and `warnings`.

## Statistics, configuration and audit

- `GET /stats` → `{"alerts": {"total", "by_severity", "by_status"}, "incidents": {"total", "by_status", "by_severity", "awaiting_human_review"}, "audit_entries"}`.
- `GET /config` → version, environment, `database_engine`, `execution_mode` (`simulation_only`), `threat_intel`
  (`mode`: `mock` / `live` / `unavailable`, `requested_provider`, `active_provider`, `fallback_reason`,
  `live_provider_implemented: true`, `live_provider_active`, and a `virustotal` object with `api_key_configured`
  (yes/no only), the limits, `url_lookups: "disabled"` and the rolling `quota` when live mode is active), `llm` (`used_by_agents: false`),
  `authentication` (`enabled: false`), the log source and sample-data paths. It contains no secrets.
- `GET /audit-logs` → `[{"id", "timestamp", "actor", "action", "target_id", "details"}]`, newest first; `action`
  filters are upper-cased.
