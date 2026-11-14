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
| `accounts` | People who sign in with a username and password (see *Accounts mode* below), and callers with a static token from `AUTH_TOKENS`. | The signed-in account's name, or the token's name. The request's reviewer field is ignored. |

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

## Accounts mode (sign-in with a password)

`AUTH_MODE=accounts` lets people sign in. No account exists by default and none is created by the software; the first one is
made from the command line.

- **Creating accounts:** `python -m app.cli.accounts create-user --username NAME --role viewer|analyst|approver`. The password is
  read with `getpass`, twice. It is never a command-line argument, a file or an environment variable. Other commands:
  `list-users`, `disable-user`, `enable-user`. The CLI creates the account tables in the database named by `DATABASE_URL` if
  they are missing.
- **Passwords:** scrypt from the standard library with N=2^17, r=8, p=1, a random 16-byte salt for each password, a 32-byte
  hash, compared in constant time. A password must be 12 to 1024 characters. Measured on the development machine: about
  0.5 s and about 128 MiB per hash. At most two hashes run at once in each process, which keeps memory bounded.
- **Signing in:** `POST /api/v1/auth/login` with JSON `{"username": ..., "password": ...}`. An unknown name, a wrong password and a
  disabled account all get the same answer, `401 Invalid username or password.`, after the same amount of work.
- **Lockout:** five failed sign-ins for one username and one client address lock that pair for 15 minutes (`429`). The lock
  also refuses the correct password. It applies to every name, existing or not, so it reveals nothing about accounts. Failures
  more than 15 minutes apart do not add up. The counters are in the database, so the lock holds across worker processes. A
  successful sign-in clears the pair's count.
- **Session:** an opaque random token (`secrets.token_urlsafe(32)`) in a cookie named `socmind_session` that is `HttpOnly`,
  `SameSite=Strict` and `Path=/`. It is `Secure` by default outside development and test, and `SESSION_COOKIE_SECURE=false` is
  refused outside them. Only the SHA-256 of the token is stored. A session ends after `SESSION_IDLE_MINUTES` (30) without use,
  and at most `SESSION_ABSOLUTE_HOURS` (8) after sign-in. It also ends on logout, and when its account is disabled, which takes
  effect on the next request.
- **CSRF:** the sign-in response and `GET /api/v1/auth/me` carry the session's CSRF token. Each `POST`, `PUT`, `PATCH` or
  `DELETE` that uses the cookie must send it in the `X-CSRF-Token` header, or the answer is `403`. Reads need no token. The
  frontend keeps the token in memory only.
- **Logout:** `POST /api/v1/auth/logout`, with the CSRF token. The session is revoked on the server, so a copy of the cookie
  stops working at once, and the browser's cookie is cleared.
- **Roles and reviewers:** unchanged. The account's role is used for every check, and the reviewer on a decision is the
  account's name.
- **Static tokens:** `AUTH_TOKENS` still work in this mode for automation. Logout does not affect them.
- **Precedence:** in this mode a valid session cookie decides the identity, even when the request also carries a bearer token.
  A write made with the cookie that lacks the CSRF token is refused (`403`); it is never taken as the bearer token instead. A
  bearer token is used only when no valid session cookie exists.
- **CSRF token, not stored:** the CSRF token is `sha256("csrf:" + session token)`, computed by the server from the cookie on each
  request. Only the session's SHA-256 is in the database, so the database holds no CSRF value.
- **Browser behaviour:** the page never attaches a bearer token in this mode, and removes one left from another mode when it
  learns the mode. Settings shows the signed-in account and its session limits instead of the token card.
- **Audit log:** `LOGIN`, `LOGIN_FAILED`, `LOGIN_LOCKED` and `LOGOUT` entries record the account name (or `(invalid username)`)
  and the client address. They never hold a password or a token. Viewers can read the audit log, so they can see sign-in
  attempts and addresses.
- **Frontend:** the sign-in page is shown until the server confirms a session, and nothing is loaded before that. A `401` from any
  request returns the user to the sign-in page and removes the data from the screen.

Required for a deployment in this mode: HTTPS in front of the backend (the cookie is `Secure`); the frontend and the API on the
same site, because `SameSite=Strict` cookies are not sent across sites; and one worker process, as for every other in-process
limit in this application.

Known limits of accounts mode:

- There is no password reset, no multi-factor authentication and no self-service registration.
- Lockout is per username and client address. It does not stop a distributed attack from many addresses, and there is no global
  limit per account. A reverse proxy that hides client addresses makes every client share one address for lockout.
- The client address is the connection's address. `X-Forwarded-For` is not trusted.
- Anything that runs in the page can use the session, as with any cookie session. The CSRF token is readable by same-origin
  scripts through `GET /api/v1/auth/me`.
- The concurrency cap on hashing is per process, so total memory is the cap multiplied by the number of worker processes.
- Passwords are not checked against lists of breached passwords.
- The timing guard for unknown names (the same work is done) is verified by tests that check the work is performed. It is not
  measured under load.

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
