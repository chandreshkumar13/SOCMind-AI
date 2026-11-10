# Security model

SOCMind AI is a decision-support prototype. It records analyst decisions and **simulates** response actions. It never
isolates a host, blocks an address, disables an account or changes a firewall, and it never executes commands found in
alerts or logs. This document says what protects the API today and what does not.

## Authentication and roles

Two modes, chosen with `AUTH_MODE`:

| Mode | Who can call the API | Reviewer name |
| --- | --- | --- |
| `disabled` (default) | Anyone who can reach the server. Every action is allowed. | Self-asserted free text from the request. |
| `token` | Only callers that send `Authorization: Bearer <token>` for an entry in `AUTH_TOKENS`. | The name on the token. The request's reviewer field is ignored. |

Roles are ordered: **viewer < analyst < approver**.

| Role | Can do |
| --- | --- |
| viewer | Read alerts, incidents, audit log, agent activity, statistics and the configuration. |
| analyst | Everything a viewer can, plus ingest, triage, enrich, delete (close) alerts, seed sample data, run the pipeline, correlate, investigate, generate recommendations and simulate an approved response. |
| approver | Everything an analyst can, plus approve or reject a proposed response. |

Responses:

- `401 Unauthorized`: no token, a malformed header, or a token that is not in `AUTH_TOKENS`. The message never repeats the token.
- `403 Forbidden`: a known token whose role is too low for the action.
- `GET /api/v1/auth/me` tells a caller its mode, name and role. `GET /api/v1/health` and `GET /api/v1/version` stay public.

Token rules, enforced at startup (`app/core/auth.py`):

- `AUTH_MODE=token` with an empty `AUTH_TOKENS` is refused. So is any token shorter than 16 characters, any role other
  than the three above, and an entry without a name. The application does not start rather than run half-configured.
- Tokens are compared with `hmac.compare_digest`. Every entry is compared, so timing does not reveal which entry matched.
- Two entries may not share a token, and a token must be printable ASCII with no spaces (it travels in a header).
- `AUTH_MODE=disabled` is refused unless `ENVIRONMENT` is `development` or `test`. Any other value, including `production`,
  must use token mode. The backend Docker image sets `ENVIRONMENT=production`, so it cannot start in demo mode by accident.
- Error messages never contain a token value, including validation errors for `AUTH_TOKENS`.
- Generate a token with `python -c "import secrets; print(secrets.token_urlsafe(32))"` and keep it out of Git and logs.
- Every API route declares its minimum role. `backend/tests/test_route_guards.py` fails when a route is added without one.
- Tokens are never returned by any endpoint (`GET /config` shows only whether token mode is on) and are never written to the
  audit log.

Where tokens live:

- Put real tokens only in `backend/.env` (git-ignored) or in the process environment. `.env.example` contains an empty list.
- The browser keeps the token it is given in `sessionStorage` (Settings → Access). It is kept for that tab only, is not
  written to `localStorage`, and is removed by "Clear token" or when the tab closes. Anyone with access to that browser tab
  while it is open can use the token.

## What is not protected

- **Demo mode has no authentication.** Do not run `AUTH_MODE=disabled` anywhere reachable by untrusted people.
- **Documentation is public.** `/docs`, `/redoc` and `/api/v1/openapi.json` describe the API but return no data, in both modes.
- **Process-local limits.** More than one worker process gives each its own run lock, VirusTotal quota, cache and circuit
  breaker, so limits are not shared. Run one worker. A startup warning is logged when `WEB_CONCURRENCY` is above 1.
- **Tokens are static.** There is no login, no expiry, no revocation without a restart, and no per-user audit beyond the
  token name. Rotating a token means editing `AUTH_TOKENS` and restarting the backend.
- **Traffic is not encrypted by the application.** Use HTTPS in front of the API (a reverse proxy) if tokens cross a network.
- **No rate limiting** on login-free API calls, and no request signing.
- **The frontend is not a security boundary.** Role checks happen in the backend; the page only shows the token field.
- **Token mode has not been tested against a real identity provider.** Only the test suite (`backend/tests/test_auth.py`)
  exercises it.

## Data handling

- **Live threat-intelligence lookups** (opt-in, `THREAT_INTEL_PROVIDER=virustotal`) send indicator values to VirusTotal:
  public IP addresses, domains and file hashes. Private, loopback, link-local and reserved addresses, and URLs, are never
  sent. Anything sent is visible to VirusTotal. Do not enable live mode for data you may not disclose.
- **Decoded command lines.** Base64 payloads in PowerShell command lines are decoded for analysis only (see
  `app/agents/enrichment/encoded_commands.py`). The decoded text is stored in the enrichment record, labelled as not executed.
  Indicators found in it are **not sent to VirusTotal** unless `VIRUSTOTAL_LOOKUP_DECODED_INDICATORS=true` is set. Without the
  flag they are reported with `lookup_status` `not_sent_decoded_disabled`. With the flag on they are looked up like any other
  indicator, with the source `decoded_command_line`. Mock lookups of them are local and are not affected.
- **Mock intelligence** is a local, offline dataset. Its hashes are synthetic labels, not real samples. Its results must not
  be read as verified intelligence.
- **Secrets.** The VirusTotal key is a `SecretStr` and is never printed, logged or returned. Tests use a fake key and a fake
  HTTP transport; they never make a network call (`tests/conftest.py` blocks outbound connections).

## Execution safety

- Response proposals are created with `requires_approval=true`, `executed=false`, `execution_mode=simulation_only`.
- Simulation writes a record of the rehearsal. Nothing else happens.
- Commands and scripts from alerts and logs are read as text. They are never executed, evaluated or passed to a shell.
  The decoder (`encoded_commands.py`) does not call any process API, and the tests make process creation raise an error to
  prove it.

## Reporting a problem

This is a prototype without a security contact. Report issues to the project team (see the README) and do not post
exploitable details publicly.
