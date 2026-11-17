# Security model

SOCMind AI is a decision-support prototype. It records analyst decisions and **simulates** response actions. It never
isolates a host, blocks an address, disables an account or changes a firewall, and it never executes commands found in
alerts or logs. This document says what protects the API today and what does not.

## Authentication and roles

Three modes, chosen with `AUTH_MODE`:

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

- `401 Unauthorized`: no token, a malformed header, or a token that is not in `AUTH_TOKENS`. In accounts mode, also no valid
  session (`Sign in to continue.`). The message never repeats the token.
- `403 Forbidden`: a known token (or signed-in account) whose role is too low for the action, or, for a cookie session, a write
  without the right CSRF token.
- `GET /api/v1/auth/me` tells a caller its mode, name and role. `GET /api/v1/auth/status` (how the server signs people in),
  `GET /api/v1/health` and `GET /api/v1/version` stay public.

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

`AUTH_MODE=accounts` lets people sign in. No account exists by default and none is created by the software on its own; the first
one is made on the first-run page or from the command line.

- **First-run setup (`POST /api/v1/auth/setup`, the page's *Create the first administrator account*):** public, accounts mode only,
  and only while the account table is **empty**. It creates one approver from a username and a password typed twice, and signs
  that person in exactly as sign-in does (cookie, CSRF token). Once any account exists, active or disabled, it answers 409 for good,
  before the body is looked at, so it cannot add accounts or take one over; if every account is disabled the page does not offer it
  (enable one with `enable-user`). The check and the insert are one SQL statement (`INSERT ... SELECT ... WHERE NOT EXISTS`), so two
  simultaneous requests, even from two processes, create one account; no password is hashed after setup has closed. It needs a JSON
  body (a cross-site HTML form cannot send one). Audit: `ACCOUNT_CREATED` with details `{"via": "first_run_setup"}`, and `LOGIN`.
  **The risk to know:** until the first account exists, whoever reaches the address first can create the administrator. Create it
  before the address is shared or reachable (or use the command line on the server first). The backend logs a warning at start-up
  while no account exists.

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
- **Managing accounts (API and Settings → Users):** an approver lists, creates, disables and enables accounts
  (`GET` and `POST /api/v1/auth/users`, `POST /api/v1/auth/users/{username}/disable` and `/enable`). These routes exist only in this
  mode (404 elsewhere) and need the `approver` role. There is no public sign-up. A new account's password follows the same rules as
  the command line's (12 to 1024 characters). A duplicate username is 409 and a bad username, role or password is 422. Disabling an
  account ends its sessions at once. Two safety rules (409): nobody disables their own account, and the last active approver is never
  disabled, so someone can always manage accounts. The rules are checked under a lock inside one process; with several worker
  processes two simultaneous requests could both pass, which is one more reason to run a single worker.
- **Resetting someone else's password (`POST /api/v1/auth/users/{username}/password`, Settings → Users → Reset password):** an
  approver sets a new password (the account rules, 12 to 1024 characters) for another account, for example when it was forgotten.
  Every open session of that account is revoked (reason `password_reset`), the old password stops working, and the account's sign-in
  lockout is cleared so it can sign in at once; a disabled account can be reset and stays disabled. An approver cannot reset their
  own password this way (409): they use *Change password*, which asks for the current one, so a stolen approver session cannot be used
  to set a password it does not know. The approver chooses the password and has to hand it over, so it should be passed in person and
  changed by its owner; the software does not force a change at the next sign-in. The same is available from the command line:
  `python -m app.cli.accounts reset-password --username NAME` (typed twice, never an argument). Audit: `PASSWORD_RESET` (actor: the
  approver; target: the account; details: the number of sessions ended), never a password.
- **Changing your own password (`POST /api/v1/auth/password`):** needs a signed-in account (a static token has none) and its CSRF
  token. The current password must be right: a wrong one is 401 and counts towards the same lockout as a wrong sign-in, so a stolen
  session cannot guess it freely. The new password follows the account rules and must differ from the current one. On success every
  other session of the account is revoked (reason `password_changed`) and the current one stays open.
- **Optional read-only guest (`ALLOW_GUEST`, default `false`):** with `AUTH_MODE=accounts` and `ALLOW_GUEST=true`, the sign-in page
  offers *Continue as guest (read-only)* and `/auth/status` says `guest_allowed: true`. `POST /api/v1/auth/guest` then opens a session
  for a **viewer named `guest`**. The setting does nothing in the other modes (the route is 404). Why this design: the session needs
  no account (the guest never appears in the account list, cannot be disabled and never counts as an approver), so nothing is added
  to the database; the session is kept in the process's memory (`app/services/guest.py`), under the same cookie, CSRF token, idle
  timeout and absolute lifetime as an account session, with only the SHA-256 of its token held, and at most 500 open at once (expired
  ones go first, then the oldest) so an anonymous caller cannot make the server grow without limit. A database row would need a
  placeholder account, and a signed cookie would need a signing secret and could not be revoked. The price is that guest sessions end
  when the backend restarts and are not shared between worker processes; a stale cookie only means "continue as guest again". A
  guest has the `viewer` role and nothing else, so every route that needs `analyst` or `approver` (including account management and
  password change) answers 403, and the automated tests check every such route. The name `guest` is reserved: no account can have it,
  so the audit log's actor `guest` is never a real person. `LOGIN` (details `guest: true`) and `LOGOUT` are audited with actor
  `guest`. **Why it is off and where it is refused:** a guest can read alerts, incidents and the audit log without a password, so
  anyone who can reach the page sees the data. It is for a private demo. Like demo mode, it is refused at start-up (the backend exits
  with a clear message) unless `ENVIRONMENT` is `development` or `test`; the check applies when `AUTH_MODE=accounts`, the only mode in
  which the setting has any effect. The backend logs a warning at start-up when it is on.
- **Responses never hold secrets:** no endpoint, log line or audit entry contains a password or a password hash, and a validation
  error (422) from any `/auth/...` route leaves out the submitted values, because FastAPI's default answer repeats the request body.
- **Session expiry warning (frontend):** `/auth/login` and `/auth/me` also return `expires_in_seconds`, counted by the server, so the
  page does not depend on its own clock. The page warns two minutes before the idle timeout (with a button that sends one light
  authenticated request, which the server counts as use) and five minutes before the absolute limit (a notice only: nothing extends
  it). When the time has passed it sends one request; a 401 returns the page to the sign-in screen. The server's own checks are
  unchanged, and the warning is a convenience, not a security control. The server records use at most once a minute, so it can end a
  session up to a minute before the page expects.
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
  and the client address. `ACCOUNT_CREATED`, `ACCOUNT_DISABLED` and `ACCOUNT_ENABLED` record the approver as the actor and the account
  as the target, `PASSWORD_CHANGED` records the account and `PASSWORD_RESET` records the approver and the account. None holds a
  password, a hash or a token. `GET /api/v1/audit-logs?category=authentication`
  returns exactly these events (the Audit Log page's *Authentication events* filter). Viewers can read the audit log, so they can see sign-in
  attempts and addresses.
- **Frontend:** the sign-in page is shown until the server confirms a session, and nothing is loaded before that. A `401` from any
  request returns the user to the sign-in page and removes the data from the screen.

Required for a deployment in this mode: HTTPS in front of the backend (the cookie is `Secure`); the frontend and the API on the
same site, because `SameSite=Strict` cookies are not sent across sites; and one worker process, as for every other in-process
limit in this application.

Known limits of accounts mode:

- There is no password reset by e-mail (a forgotten password is reset by an approver, who then knows the new one until its owner
  changes it), no multi-factor authentication and no self-service registration. First-run setup is open to whoever reaches an
  installation with no account first (see above). Guest sessions live in one process's memory and end on restart. A password change does not check the new
  password against lists of breached passwords, and a failed password change is counted towards the lockout but not written to the
  audit log as a separate event.
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
- **Documentation is public.** `/docs`, `/redoc` and `/api/v1/openapi.json` describe the API but return no data, in every mode.
- **Process-local limits.** More than one worker process gives each its own run lock, VirusTotal quota, cache and circuit
  breaker, so limits are not shared. Run one worker. A startup warning is logged when `WEB_CONCURRENCY` is above 1.
- **Tokens are static.** A token has no sign-in step, no expiry, no revocation without a restart, and no per-user audit beyond
  the token name. Rotating a token means editing `AUTH_TOKENS` and restarting the backend. Use accounts mode for people who
  sign in.
- **Traffic is not encrypted by the application.** Use HTTPS in front of the API (a reverse proxy) if tokens cross a network.
- **No general rate limiting** on API calls (the only limit is the sign-in lockout in accounts mode), and no request signing.
- **The frontend is not a security boundary.** Role checks happen in the backend; the page only shows the token field or the
  sign-in page.
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
