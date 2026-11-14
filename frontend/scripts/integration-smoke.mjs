// Frontend <-> backend integration test.
//
// Starts the REAL FastAPI backend on a free port with a throw-away SQLite database (your socmind.db is never
// opened), runs the whole workflow over HTTP through the frontend's own api.js client, then renders the page
// components with the live responses and checks what an analyst would see.
//
//   npm run test:integration            (needs Python with the backend requirements installed)
//   PYTHON=python3 npm run test:integration
//
// It cannot run a browser: it renders React to HTML on the server, so clicks and layout are not covered.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const backend = path.resolve(frontend, '..', 'backend');
const python = process.env.PYTHON || 'python';

const failures = [];
let passed = 0;
const check = (name, text, ...needles) => {
  const missing = needles.filter((n) => (n instanceof RegExp ? !n.test(text) : !String(text).includes(n)));
  if (missing.length) failures.push(`${name}: missing ${missing.map(String).join(' | ')}`); else passed += 1;
};
const absent = (name, text, ...needles) => {
  const present = needles.filter((n) => String(text).includes(n));
  if (present.length) failures.push(`${name}: should not contain ${present.join(' | ')}`); else passed += 1;
};
const expect = (name, ok, detail = '') => { if (ok) passed += 1; else failures.push(`${name}${detail ? `: ${detail}` : ''}`); };

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  s.on('error', reject);
});


// ---- accounts mode, over real HTTP against a real backend on its own throw-away database.
// The account is created by the backend's own account service, with a random password that exists only for this run and is
// passed in the environment of that one child process (getpass cannot read piped input on Windows, so the CLI is not used here;
// tests/test_accounts_cli.py covers the CLI). Node's fetch keeps no cookie jar, so the cookie is carried by hand. That checks the
// contract the browser relies on; it does not prove the browser's own cookie handling.
async function accountsModeCheck() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socmind-acc-'));
  const accPort = await freePort();
  const accBase = `http://127.0.0.1:${accPort}/api/v1`;
  const password = crypto.randomBytes(18).toString('base64url');
  const staticToken = crypto.randomBytes(18).toString('base64url');
  const env = {
    ...process.env,
    THREAT_INTEL_PROVIDER: 'mock', THREAT_INTEL_MOCK_MODE: 'True', VIRUSTOTAL_API_KEY: '',
    AUTH_MODE: 'accounts', AUTH_TOKENS: JSON.stringify([{ name: 'Automation', role: 'viewer', token: staticToken }]), ENVIRONMENT: 'development',
    DATABASE_URL: `sqlite:///${path.join(dir, 'accounts.db').replace(/\\/g, '/')}`,
    PYTHONDONTWRITEBYTECODE: '1',
  };
  let acc = null;
  let accLog = '';
  try {
    // The program is built from lines and joined with a newline character, so no escape sequences are needed.
    const pythonLines = [
      'import os',
      'from app.db.session import init_db, SessionLocal',
      'from app.services import accounts',
      'init_db()',
      'db = SessionLocal()',
      'accounts.create_user(db, "ana.analyst", "analyst", os.environ["SOCMIND_IT_PASSWORD"])',
      'print("created")',
    ];
    const made = await new Promise((resolve) => {
      const p = spawn(python, ['-c', pythonLines.join(String.fromCharCode(10))], { cwd: backend, env: { ...env, SOCMIND_IT_PASSWORD: password } });
      let out = '';
      p.stdout.on('data', (d) => { out += d; });
      p.stderr.on('data', (d) => { out += d; });
      p.on('close', (code) => resolve({ code, out }));
    });
    expect('an account is created for the run', made.code === 0 && made.out.includes('created'), made.out.slice(-300));

    acc = spawn(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(accPort), '--log-level', 'warning'], { cwd: backend, env });
    acc.stdout.on('data', (d) => { accLog += d; });
    acc.stderr.on('data', (d) => { accLog += d; });
    let up = false;
    for (let i = 0; i < 80 && !up; i += 1) {
      try { up = (await fetch(`${accBase}/health`)).ok; } catch { await new Promise((r) => setTimeout(r, 250)); }
    }
    if (!up) throw new Error(`accounts backend did not start: ${accLog.slice(-600)}`);

    const status = await (await fetch(`${accBase}/auth/status`)).json();
    expect('status says sign-in is required', status.mode === 'accounts' && status.sign_in === true, JSON.stringify(status));
    expect('protected data is refused before sign-in', (await fetch(`${accBase}/alerts`)).status === 401);

    const wrong = await fetch(`${accBase}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'ana.analyst', password: 'not-the-password-0' }) });
    expect('a wrong password is refused with the generic message', wrong.status === 401 && (await wrong.json()).detail === 'Invalid username or password.');

    const login = await fetch(`${accBase}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'ana.analyst', password }) });
    expect('the right password signs in', login.status === 200, String(login.status));
    const setCookie = login.headers.get('set-cookie') || '';
    expect('the session cookie is HttpOnly and SameSite=Strict', /HttpOnly/i.test(setCookie) && /SameSite=Strict/i.test(setCookie), setCookie);
    const cookie = setCookie.split(';')[0];
    const session = await login.json();
    expect('the session token is not in the response body', cookie.length > 20 && !JSON.stringify(session).includes(cookie.split('=')[1]));
    expect('the password is not in the response body', !JSON.stringify(session).includes(password));
    const csrf = session.csrf_token;
    expect('a CSRF token is issued with the session', typeof csrf === 'string' && csrf.length >= 40);

    const me = await (await fetch(`${accBase}/auth/me`, { headers: { Cookie: cookie } })).json();
    expect('the session identifies the account and its role', me.name === 'ana.analyst' && me.role === 'analyst' && me.csrf_token === csrf, JSON.stringify(me));
    expect('reads work with the cookie alone', (await fetch(`${accBase}/alerts`, { headers: { Cookie: cookie } })).status === 200);
    const refreshed = await (await fetch(`${accBase}/auth/me`, { headers: { Cookie: cookie } })).json();
    expect('a page refresh (a second read with the same cookie) keeps the same account', refreshed.name === 'ana.analyst');
    const both = { Cookie: cookie, Authorization: `Bearer ${staticToken}` };
    const precedence = await (await fetch(`${accBase}/auth/me`, { headers: both })).json();
    expect('with a cookie and a bearer token together, the cookie account is the identity', precedence.mode === 'accounts' && precedence.name === 'ana.analyst', JSON.stringify(precedence));
    expect('a write with the cookie and a bearer token but no CSRF token is refused, not taken as the bearer', (await fetch(`${accBase}/alerts/seed`, { method: 'POST', headers: both })).status === 403);
    expect('a bearer token still works alone when no cookie is sent', (await fetch(`${accBase}/alerts`, { headers: { Authorization: `Bearer ${staticToken}` } })).status === 200);
    expect('a write without the CSRF header is refused', (await fetch(`${accBase}/alerts/seed`, { method: 'POST', headers: { Cookie: cookie } })).status === 403);
    expect('a write with the CSRF header works for an analyst', (await fetch(`${accBase}/alerts/seed`, { method: 'POST', headers: { Cookie: cookie, 'X-CSRF-Token': csrf } })).status === 200);

    const out = await fetch(`${accBase}/auth/logout`, { method: 'POST', headers: { Cookie: cookie, 'X-CSRF-Token': csrf } });
    expect('logout succeeds with the CSRF header', out.status === 200 && (await out.json()).authenticated === false);
    expect('the cookie is cleared by logout', /Max-Age=0/i.test(out.headers.get('set-cookie') || ''));
    expect('the old cookie is refused after logout (server-side revocation)', (await fetch(`${accBase}/auth/me`, { headers: { Cookie: cookie } })).status === 401);
  } catch (err) {
    failures.push(`accounts-mode check crashed: ${err.stack || err}`);
  } finally {
    if (acc && !acc.killed) acc.kill();
    await new Promise((r) => setTimeout(r, 300));
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

// ---- token mode, over real HTTP on its own backend and database. Sign-in is not offered; the static bearer token is the only
// credential, and a cookie alone counts for nothing.
async function tokenModeCheck() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socmind-tok-'));
  const tokPort = await freePort();
  const tokBase = `http://127.0.0.1:${tokPort}/api/v1`;
  const bearer = crypto.randomBytes(18).toString('base64url');
  const env = {
    ...process.env,
    THREAT_INTEL_PROVIDER: 'mock', THREAT_INTEL_MOCK_MODE: 'True', VIRUSTOTAL_API_KEY: '',
    AUTH_MODE: 'token', AUTH_TOKENS: JSON.stringify([{ name: 'Automation', role: 'analyst', token: bearer }]), ENVIRONMENT: 'development',
    DATABASE_URL: `sqlite:///${path.join(dir, 'token.db').replace(/\\/g, '/')}`,
    PYTHONDONTWRITEBYTECODE: '1',
  };
  let proc = null;
  let log = '';
  try {
    proc = spawn(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(tokPort), '--log-level', 'warning'], { cwd: backend, env });
    proc.stdout.on('data', (d) => { log += d; });
    proc.stderr.on('data', (d) => { log += d; });
    let up = false;
    for (let i = 0; i < 80 && !up; i += 1) {
      try { up = (await fetch(`${tokBase}/health`)).ok; } catch { await new Promise((r) => setTimeout(r, 250)); }
    }
    if (!up) throw new Error(`token backend did not start: ${log.slice(-600)}`);
    const status = await (await fetch(`${tokBase}/auth/status`)).json();
    expect('token mode: status requires a token and does not offer sign-in', status.mode === 'token' && status.login_required === true && status.sign_in === false, JSON.stringify(status));
    expect('token mode: sign-in is not offered (404)', (await fetch(`${tokBase}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status === 404);
    expect('token mode: protected data needs the bearer token (401 without it)', (await fetch(`${tokBase}/alerts`)).status === 401);
    expect('token mode: a bearer token gets in', (await fetch(`${tokBase}/alerts`, { headers: { Authorization: `Bearer ${bearer}` } })).status === 200);
    expect('token mode: the token identity and role are reported', (await (await fetch(`${tokBase}/auth/me`, { headers: { Authorization: `Bearer ${bearer}` } })).json()).role === 'analyst');
    expect('token mode: a wrong token is refused (401)', (await fetch(`${tokBase}/alerts`, { headers: { Authorization: 'Bearer not-the-token-0123456789' } })).status === 401);
    expect('token mode: a write with the token needs no CSRF header', (await fetch(`${tokBase}/alerts/seed`, { method: 'POST', headers: { Authorization: `Bearer ${bearer}` } })).status === 200);
  } catch (err) {
    failures.push(`token-mode check crashed: ${err.stack || err}`);
  } finally {
    if (proc && !proc.killed) proc.kill();
    await new Promise((r) => setTimeout(r, 300));
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'socmind-it-'));
const port = await freePort();
const base = `http://127.0.0.1:${port}/api/v1`;
let server = null;
let child = null;
let childLog = '';

async function cleanup() {
  if (server) await server.close().catch(() => {});
  if (child && !child.killed) child.kill();
  await new Promise((r) => setTimeout(r, 300));
  fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}

try {
  child = spawn(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'], {
    cwd: backend,
    env: {
      ...process.env,
      // Hermetic: this test must never reach a live threat-intelligence provider, whatever backend/.env or the shell says.
      THREAT_INTEL_PROVIDER: 'mock',
      THREAT_INTEL_MOCK_MODE: 'True',
      VIRUSTOTAL_API_KEY: '',
      DATABASE_URL: `sqlite:///${path.join(tmp, 'it.db').replace(/\\/g, '/')}`,
      PYTHONDONTWRITEBYTECODE: '1',
    },
  });
  child.stdout.on('data', (d) => { childLog += d; });
  child.stderr.on('data', (d) => { childLog += d; });
  child.on('error', (e) => { childLog += `spawn error: ${e.message}`; });

  let up = false;
  for (let i = 0; i < 80 && !up; i += 1) {
    try { up = (await fetch(`${base}/health`)).ok; } catch { await new Promise((r) => setTimeout(r, 250)); }
  }
  if (!up) throw new Error(`backend did not start on port ${port}. Is Python with the backend requirements available as "${python}"?\n${childLog.slice(-800)}`);

  const preflight = await (await fetch(`${base}/config`)).json();
  if (preflight.threat_intel.active_provider !== 'mock' || preflight.threat_intel.virustotal.api_key_configured) {
    throw new Error('Refusing to run: the integration backend is not on the offline mock provider, so the test would make live lookups.');
  }

  // Use the frontend's own client against the live backend
  process.env.VITE_API_BASE = base;
  const vite = await import(pathToFileURL(path.join(frontend, 'node_modules/vite/dist/node/index.js')).href);
  const React = (await import(pathToFileURL(path.join(frontend, 'node_modules/react/index.js')).href)).default;
  const { renderToStaticMarkup } = (await import(pathToFileURL(path.join(frontend, 'node_modules/react-dom/server.js')).href)).default;
  server = await vite.createServer({ root: frontend, server: { middlewareMode: true }, appType: 'custom', logLevel: 'error' });
  const { api, ApiError, API_BASE } = await server.ssrLoadModule('/src/api.js');
  const h = React.createElement;
  const html = (el) => renderToStaticMarkup(el);
  expect('client targets the live backend', API_BASE === base, API_BASE);

  // ---- CORS: the dev server origin may call the API
  const pre = await fetch(`${base}/alerts`, { method: 'OPTIONS', headers: { Origin: 'http://localhost:5173', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
  expect('CORS preflight allows the Vite origin', pre.headers.get('access-control-allow-origin') === 'http://localhost:5173', String(pre.status));

  // ---- empty system: honest empty states, no demo data
  const emptyStats = await api('/stats');
  expect('fresh database is empty', emptyStats.alerts.total === 0 && emptyStats.incidents.total === 0);
  const emptyRun = await api('/pipeline/run', { method: 'POST' });
  expect('pipeline on an empty database succeeds with nothing to do', emptyRun.outcome === 'success' && emptyRun.alerts_in_scope === 0);

  // ---- full workflow through the client
  const seeded = await api('/alerts/seed', { method: 'POST' });
  expect('sample alerts load only on request', seeded.inserted === 10);
  const run = await api('/pipeline/run', { method: 'POST' });
  expect('pipeline outcome', run.outcome === 'success' && run.status === 'completed' && run.incidents_created.length === 2, JSON.stringify(run.stages.map((s) => [s.agent, s.status])));
  const rerun = await api('/pipeline/run', { method: 'POST' });
  expect('re-running creates nothing new', rerun.incidents_created.length === 0 && rerun.stages.every((s) => s.processed === 0));

  const alerts = await api('/alerts?limit=100');
  const incidents = await api('/incidents?limit=100');
  const stats = await api('/stats');
  const cfg = await api('/config');
  const agents = await api('/agents');
  const runs = await api('/pipeline/runs?limit=5');
  expect('stats are consistent', stats.alerts.total === alerts.length && stats.incidents.total === incidents.length && stats.incidents.awaiting_human_review === 2);
  expect('config is non-secret and simulation-only', cfg.execution_mode === 'simulation_only' && !JSON.stringify(cfg).toLowerCase().includes('api_key"'));
  expect('live lookups are implemented but opt-in: the default backend stays on the mock',
    cfg.threat_intel.mode === 'mock' && cfg.threat_intel.live_provider_implemented === true && cfg.threat_intel.live_provider_active === false
      && cfg.threat_intel.virustotal.api_key_configured === false && cfg.threat_intel.virustotal.quota === null);
  expect('agent activity is derived from the audit log', agents.find((a) => a.name === 'Triage Agent').total_actions === 10);

  const fin = incidents.find((i) => i.correlated_alert_ids.includes('ALT-2026-001'));
  const dc = incidents.find((i) => i.correlated_alert_ids.includes('ALT-2026-006'));
  const pending = await api(`/incidents/${fin.id}`);

  // ---- error handling through the client
  let notFound = null;
  try { await api('/incidents/NOPE'); } catch (e) { notFound = e; }
  expect('404 becomes a readable ApiError', notFound instanceof ApiError && notFound.status === 404 && /NOPE/.test(notFound.message), String(notFound));
  let invalid = null;
  try { await api(`/incidents/${fin.id}/approve`, { method: 'POST', body: { reviewer: '' } }); } catch (e) { invalid = e; }
  expect('validation error is readable', invalid instanceof ApiError && invalid.status === 422 && /reviewer/.test(invalid.message), String(invalid));
  let early = null;
  try { await api(`/incidents/${fin.id}/simulate`, { method: 'POST', body: { reviewer: 'Tester' } }); } catch (e) { early = e; }
  expect('simulation before approval is refused', early instanceof ApiError && early.status === 409, String(early));

  // ---- approve + simulate two different incidents so both end states can be rendered
  await api(`/incidents/${dc.id}/approve`, { method: 'POST', body: { reviewer: 'Test Analyst', reason: 'integration test' } });
  const approved = await api(`/incidents/${dc.id}`);
  await api(`/incidents/${fin.id}/approve`, { method: 'POST', body: { reviewer: 'Test Analyst' } });
  await api(`/incidents/${fin.id}/simulate`, { method: 'POST', body: { reviewer: 'Test Analyst' } });
  const simulated = await api(`/incidents/${fin.id}`);
  expect('approve leaves the incident un-executed', approved.status === 'RESPONSE_APPROVED' && approved.details.recommendations.every((r) => r.executed === false));
  expect('simulation is recorded, nothing executed', simulated.status === 'RESPONSE_SIMULATED' && simulated.details.simulation.status === 'SIMULATED' && simulated.details.recommendations.every((r) => r.executed === false));
  const audit = await api('/audit-logs?action=INCIDENT_APPROVED&limit=10');
  expect('approvals are audited with the reviewer as actor', audit.length === 2 && audit.every((a) => a.actor === 'Test Analyst'));

  // ---- render the pages with the live data
  const load = (p) => server.ssrLoadModule(p);
  const Inc = await load('/src/pages/Incidents.jsx');
  const Alerts = await load('/src/pages/Alerts.jsx');
  // alert search: the alert ID and IP addresses are searchable, not only title, source, host and user
  const searchAlert = { id: 'ALT-2026-E1082F', alert_title: 'Synthetic Test Ingestion', source: 'CrowdStrike EDR', host: 'FIN-WKS-042', username: 'j.doe', source_ip: '203.0.113.10', destination_ip: '203.0.113.30' };
  expect('alert search finds an alert by its id, ignoring case and spaces', Alerts.alertMatchesSearch(searchAlert, '  alt-2026-e1082f '));
  expect('alert search finds an alert by an IP address', Alerts.alertMatchesSearch(searchAlert, '203.0.113.30'));
  expect('alert search still finds title, source, host and user', ['synthetic', 'crowdstrike', 'fin-wks', 'j.doe'].every((q) => Alerts.alertMatchesSearch(searchAlert, q)));
  expect('alert search returns nothing for an unrelated term', !Alerts.alertMatchesSearch(searchAlert, 'nothing-like-this'));
  expect('an empty alert search matches every alert', Alerts.alertMatchesSearch(searchAlert, ''));
  // server-side search reaches every alert; the view helpers build the same request the page sends
  const view = await load('/src/lib/view.js');
  const byPaddedId = await api(view.alertSearchPath('  ALT-2026-004  '));
  expect('server search by a padded id finds that alert', byPaddedId.some((a) => a.id === 'ALT-2026-004'));
  expect('server search for an unknown term finds nothing', (await api(view.alertSearchPath('zz-no-such-alert-zz'))).length === 0);
  expect('an empty search sends no request', view.alertSearchPath('   ') === null);
  expect('a full page of matches gets the cap note', view.searchCapNote(100).includes('capped at 100') && view.searchCapNote(99) === '');
  const Dash = await load('/src/pages/Dashboard.jsx');
  const Agents = await load('/src/pages/AgentActivity.jsx');
  const Audit = await load('/src/pages/AuditLog.jsx');
  const Settings = await load('/src/pages/Settings.jsx');
  const Report = await load('/src/components/PipelineRunReport.jsx');
  const Side = await load('/src/components/Sidebar.jsx');
  const Top = await load('/src/components/Topbar.jsx');
  const noop = () => {};
  const fullMock = () => ({ agent: 'Enrichment Agent', status: 'completed', alert_id: 'X', intel_mode: 'mock', verified: false, total_iocs_extracted: 1,
    summary: { malicious: 1, suspicious: 0, clean: 0, unknown: 0 }, disclaimer: 'Results come from LOCAL MOCK threat intelligence',
    iocs: [{ value: '185.220.101.5', type: 'IP', source: 'destination_ip', reputation: 'MALICIOUS', confidence: 0.95, provider: 'MockThreatIntel', evidence: 'mock' }] });

  let t = html(h(Inc.default, { incidents: await api('/incidents'), loading: false, error: null, refresh: noop, refreshAlerts: noop }));
  check('incident list', t, fin.id, 'FINANCE-WKS-042', 'Decision: APPROVED · simulated', 'Decision: APPROVED · not executed');
  // ---- incident list: search, filtering and sorting on the live list (the rules are pure, so they run on real data)
  const IncFilters = await load('/src/lib/incidentFilters.js');
  const liveList = await api('/incidents?limit=100');
  const liveVisible = liveList.filter((i) => i.status !== 'MERGED');
  const approvedApi = liveVisible.filter((i) => i.human_approval_status === 'APPROVED').length;
  expect('approval filter matches the stored decisions', IncFilters.filterAndSortIncidents(liveList, { approval: 'APPROVED' }).length === approvedApi);
  expect('search finds an incident by its host, ignoring case and spaces',
    IncFilters.filterAndSortIncidents(liveList, { search: '  finance-wks  ' }).some((i) => i.id === fin.id));
  const newestFirst = IncFilters.filterAndSortIncidents(liveList, {});
  expect('the default order is newest first',
    newestFirst.every((v, k, arr) => k === 0 || (IncFilters.timeValue(arr[k - 1].created_at) ?? 0) >= (IncFilters.timeValue(v.created_at) ?? 0)));
  expect('the list never includes merged incidents', newestFirst.length === liveVisible.length && newestFirst.every((i) => i.status !== 'MERGED'));
  const byAlerts = IncFilters.filterAndSortIncidents(liveList, { sort: 'alerts' });
  expect('most alerts first', byAlerts.every((v, k, arr) => k === 0 || arr[k - 1].correlated_alert_ids.length >= v.correlated_alert_ids.length));
  t = html(h(Inc.default, { incidents: liveList, loading: false, error: null, refresh: noop, refreshAlerts: noop }));
  check('incident list shows the search bar, filters and the count', t, 'Search incidents', 'Any approval', 'Any status', 'Newest first',
    `Showing ${newestFirst.length} of ${liveVisible.length} incident`);
  absent('the default view offers no clear button', t, 'Clear filters');
  absent('incident list has no demo data', t, 'INC-2026-089', 'Simulated Action');
  t = html(h(Inc.Investigation, { inv: pending.details.investigation }));
  check('investigation separates evidence classes', t, /Verified facts[\s\S]*Mock threat intelligence[\s\S]*Hypotheses/, 'Log source:', 'synthetic', 'UTC');
  t = html(h(Inc.Recommendations, { details: simulated.details }));
  check('recommendations', t, 'NOT EXECUTED', 'Simulation: SIMULATED', 'Risk if wrong', 'Rollback', 'Required approvals');
  absent('nothing is shown as executed', t, '>EXECUTED<');
  absent('a decision in force is never shown as superseded history', t, 'Superseded recommendations');
  t = html(h(Inc.Review, { incident: pending, onDecide: noop, busy: false }));
  check('pending review', t, 'Approve proposal', 'Reject proposal');
  t = html(h(Inc.Simulation, { incident: approved, onSimulate: noop, busy: false }));
  check('approved incident offers a simulation, not an execution', t, 'Run simulation (no real action)', 'Approved is not executed');
  absent('no execute button', t, 'Execute');
  t = html(h(Inc.Simulation, { incident: simulated, onSimulate: noop, busy: false }));
  check('simulated incident shows the record', t, 'SIMULATED', 'Test Analyst', 'No command was run');
  absent('simulated incident cannot be simulated twice', t, 'Run simulation');
  t = html(h(Inc.Simulation, { incident: pending, onSimulate: noop, busy: false }));
  expect('undecided incident shows no simulation panel', t === '');

  // ---- a decided incident: re-investigating it asks first, then withdraws the decision and supersedes its recommendations
  const Stale = (await load('/src/components/StaleNotice.jsx')).default;
  const notice = view.reinvestigationNotice(approved);
  t = html(h(Inc.ReinvestigateConfirm, { notice, busy: false, onConfirm: noop, onCancel: noop }));
  check('re-investigating a decided incident asks first', t, 'Withdraw the recorded decision?', 'will be withdrawn and saved in the review history',
    'Test Analyst', 'Withdraw decision and re-investigate', 'Cancel');
  expect('a pending incident needs no confirmation',
    view.reinvestigationNotice(pending) === null && html(h(Inc.ReinvestigateConfirm, { notice: null, busy: false, onConfirm: noop, onCancel: noop })) === '');
  await api(`/incidents/${dc.id}/investigate`, { method: 'POST' });
  const withdrawn = await api(`/incidents/${dc.id}`);
  expect('re-investigation withdraws the approval and keeps it in the review history',
    withdrawn.human_approval_status === 'PENDING' && withdrawn.details.review_history?.length === 1
      && withdrawn.details.review_history[0].review.decision === 'APPROVED');
  expect('withdrawn recommendations are superseded, never current',
    withdrawn.details.recommendations.length > 0
      && withdrawn.details.recommendations.every((r) => r.status === 'SUPERSEDED' && r.simulation_status === 'SUPERSEDED' && r.executed === false));
  expect('the primary action is cleared, and the withdrawn one is kept in history',
    withdrawn.recommended_action === null && withdrawn.details.review_history[0].recommended_action === approved.recommended_action);
  t = html(h(Inc.Recommendations, { details: withdrawn.details }));
  check('superseded recommendations are labelled as history', t, 'Superseded recommendations, not current', 'SUPERSEDED', 'withdrawn');
  absent('superseded recommendations never show as approved or simulated', t, '>APPROVED<', 'Simulation: SIMULATED', 'Run simulation', 'Approve proposal');
  t = html(h(Inc.ReviewHistory, { history: withdrawn.details.review_history }));
  check('review history keeps the decision, when it was withdrawn and what it was based on', t, 'Earlier decisions (historical', 'Test Analyst',
    'Withdrawn', 'Recommendations at the time', 'APPROVED');
  t = html(h(Inc.Review, { incident: withdrawn, onDecide: noop, busy: false }));
  check('a withdrawn incident says why it cannot be approved yet', t, 'superseded when an earlier decision was withdrawn');
  absent('a withdrawn incident offers no approve button', t, 'Approve proposal');
  t = html(h(Stale, { details: withdrawn.details }));
  check('the stale notice explains the superseded state', t, 'Recommendations superseded', 'Generate new recommendations before deciding');
  absent('the superseded state is not described as changed data', t, 'alert data or threat intelligence changed');
  t = html(h(Inc.Simulation, { incident: withdrawn, onSimulate: noop, busy: false }));
  expect('a withdrawn incident shows no simulation panel', t === '');

  t = html(h(Dash.default, { alerts, incidents, stats, setActiveTab: noop }));
  check('dashboard', t, 'Alerts In Queue', 'Awaiting Human Review', '>10<');
  absent('dashboard has no fabricated metrics', t, 'MTTR', '-78%');
  t = html(h(Alerts.default, { alerts: alerts.slice(0, 3), loading: false, error: null, refreshAlerts: noop, seedSampleAlerts: noop, totalAlerts: 10, alertsTotal: 10, loadMoreAlerts: noop, loadingMore: false }));
  check('alerts list says how many are loaded and offers load more', t, 'Showing 3 of 10 alerts.', 'Load more');
  check('alerts page offers a status filter with every backend status', t, 'Filter by alert status', 'Any status', 'New', 'Triaged', 'Enriched', 'Correlated', 'Investigating', 'Closed');
  check('alerts page says both filters apply to the loaded alerts', t, 'The severity and status filters apply to the loaded alerts');
  const closeProps = { alert: { id: 'ALT-X', status: 'TRIAGED' }, confirming: false, busy: false, error: null, onAsk: noop, onCancel: noop, onConfirm: noop };
  t = html(h(Alerts.CloseAlertControl, closeProps));
  check('close control: an open alert shows a Close alert button', t, 'Close alert');
  absent('close control: no confirmation before the first click', t, 'Confirm close', 'It cannot be reopened');
  t = html(h(Alerts.CloseAlertControl, { ...closeProps, confirming: true }));
  check('close control: the confirmation says what closing does and that nothing is executed', t,
    'This marks the alert CLOSED and removes it from active incidents. It cannot be reopened. Nothing is executed.', 'Confirm close', 'Cancel');
  t = html(h(Alerts.CloseAlertControl, { ...closeProps, alert: { id: 'ALT-X', status: 'CLOSED' } }));
  check('close control: a closed alert says it cannot be reopened', t, 'This alert is CLOSED', 'cannot be reopened');
  expect('close control: the Close alert button is disabled for a closed alert', /disabled=""[^>]*>Close alert</.test(t), t.slice(0, 300));
  t = html(h(Alerts.CloseAlertControl, { ...closeProps, error: 'This action needs the analyst role.' }));
  check('close control: a failure is shown in an error card', t, 'Could not close the alert', 'This action needs the analyst role.');
  const full = await api('/alerts/ALT-2026-001');
  t = html(h(Alerts.AnalysisPanels, { alert: full, busy: false, onRun: noop, runError: null }));
  check('alert analysis shows triage and mock enrichment', t, 'Score', 'MALICIOUS', 'LOCAL MOCK', 'incident');
  check('mock state keeps its label, disclaimer and timestamp', t, 'Local mock (unverified)', 'Reputation (mock)', 'not a verified live feed', 'Recorded ');
  absent('mock state never claims a live source', t, 'VirusTotal', 'Lookup');
  // ---- stale drawer: an open record is replaced by the list's copy only when that copy is newer (real backend data)
  const { refreshedSelection } = await server.ssrLoadModule('/src/lib/view.js');
  const opened = await api('/alerts/ALT-2026-002');
  await api('/alerts/ALT-2026-002/enrich', { method: 'POST' });
  const listed = await api('/alerts?limit=100');
  const replaced = refreshedSelection(opened, listed);
  expect('open drawer record is replaced by the newer stored enrichment',
    replaced.updated_at > opened.updated_at && replaced.normalized_data.enrichment.timestamp !== opened.normalized_data.enrichment.timestamp,
    `${opened.updated_at} -> ${replaced.updated_at}`);
  expect('an older list never replaces a newer open record', refreshedSelection(replaced, [opened]) === replaced);
  // ---- a no-op re-enrichment (same verdicts) must leave every incident's analysis fresh
  await api('/alerts/ALT-2026-001/enrich', { method: 'POST' });
  const afterNoop = await api('/incidents?limit=100');
  expect('a no-op re-enrichment leaves every incident fresh',
    afterNoop.length > 0 && afterNoop.every((i) => i.details.investigation_stale === false && !(i.details.stale_reasons || []).length));
  // ---- stale notice: silent when fresh, names what changed when stale
  const StaleNotice = (await load('/src/components/StaleNotice.jsx')).default;
  expect('fresh incident shows no out-of-date notice', html(h(StaleNotice, { details: { investigation_stale: false, recommendations_stale: false } })) === '');
  const staleHtml = html(h(StaleNotice, { details: { investigation_stale: true, recommendations_stale: true, stale_reasons: [
    { alert_id: 'ALT-2026-001', change: 'threat-intelligence source changed: mock -> live (VirusTotal)', at: '2026-10-28T09:30:53.035226Z' }] } }));
  check('stale notice names the analysis and the change', staleHtml, 'Out of date', 'the investigation and the recommendations',
    'ALT-2026-001', 'live (VirusTotal)', '2026-10-28 09:30:53 UTC');
  check('stale notice without reasons still explains', html(h(StaleNotice, { details: { investigation_stale: false, recommendations_stale: true } })), 'the recommendations were produced');
  const legacyHtml = html(h(StaleNotice, { details: { investigation_stale: true, recommendations_stale: true, stale_reasons: [
    { alert_id: null, change: 'analysis was built before change tracking; refreshing it from the latest alert data', at: '2026-10-28T09:30:53.035226Z' }] } }));
  check('legacy reason is shown without a null alert id', legacyHtml, 'before change tracking');
  absent('legacy reason never prints a null alert id', legacyHtml, 'null:');
  // ---- live-mode (VirusTotal) presentation, rendered from live-shaped data (no VirusTotal call is made here)
  const liveEnr = {
    agent: 'Enrichment Agent', status: 'completed', alert_id: 'X', intel_mode: 'live', provider: 'VirusTotal', verified: false, incomplete: true,
    total_iocs_extracted: 4, summary: { malicious: 1, suspicious: 0, clean: 1, unknown: 2 },
    disclaimer: "Reputation reported by VirusTotal's public API ... It is not independently verified by SOCMind AI.",
    iocs: [
      { value: '185.220.101.5', type: 'IP', source: 'destination_ip', reputation: 'MALICIOUS', confidence: 0.17, provider: 'VirusTotal', lookup_status: 'completed',
        evidence: '12 of 70 engines flagged it as malicious (VirusTotal).', detections: { malicious: 12, suspicious: 0, harmless: 50, undetected: 8, total: 70 },
        reference_url: 'https://www.virustotal.com/gui/ip-address/185.220.101.5', cached: true },
      { value: '10.0.0.5', type: 'IP', source: 'source_ip', reputation: 'UNKNOWN', confidence: 0, provider: 'none', lookup_status: 'skipped_non_public_ip', evidence: 'Not sent to VirusTotal' },
      { value: '8.8.8.8', type: 'IP', source: 'description', reputation: 'UNKNOWN', confidence: 0, provider: 'none', lookup_status: 'rate_limited', evidence: 'Not looked up: quota' },
      { value: 'evil.example.net', type: 'DOMAIN', source: 'description', reputation: 'CLEAN', confidence: 0.5, provider: 'VirusTotal', lookup_status: 'completed',
        evidence: '0 of 70 engines flagged it.', detections: { malicious: 0, suspicious: 0, harmless: 60, undetected: 10, total: 70 },
        reference_url: 'javascript:alert(document.cookie)' },
    ],
  };
  t = html(h(Alerts.AnalysisPanels, { alert: { id: 'X', status: 'ENRICHED', normalized_data: { enrichment: liveEnr } }, busy: false, onRun: noop, runError: null }));
  check('live alert analysis', t, 'Reputation (VirusTotal)', '>Lookup<', 'Quota reached, retry later', 'Private or reserved: not sent', '12/70 engines flagged',
    'from cache', 'could not be checked yet', 'not independently verified');
  check('live alert links only to VirusTotal', t, 'href="https://www.virustotal.com/gui/ip-address/185.220.101.5"', 'rel="noopener noreferrer"');
  absent('hostile reference url is never rendered as a link', t, 'javascript:');
  t = html(h(Alerts.AnalysisPanels, { alert: { id: 'X', status: 'ENRICHED', normalized_data: { enrichment: { ...fullMock(), fallback_reason: 'VIRUSTOTAL_API_KEY is not configured', requested_provider: 'virustotal' } } }, busy: false, onRun: noop, runError: null }));
  check('mock fallback is labelled on the alert', t, 'Reputation (mock)', 'Live lookups were requested but are not active', 'VIRUSTOTAL_API_KEY is not configured');
  absent('mock results show no live Lookup column', t, '>Lookup<');
  const liveInv = {
    summary: 'Incident I groups 2 alert(s).', evidence_strength: 'moderate', log_records_used: 0, limitations: ['Threat intelligence comes from VirusTotal and is not independently verified'],
    entities: { hosts: ['H'], users: [], ips: [], hashes: [], domains: [] }, timeline: [],
    findings: [{ type: 'verified', statement: 'Two alerts.', basis: [] },
      { type: 'external_intel', statement: 'VirusTotal reports IP 185.220.101.5 as malicious: 12 of 70 engines. Not independently verified by SOCMind AI.', basis: [], reference_url: 'https://www.virustotal.com/gui/ip-address/185.220.101.5' },
      { type: 'external_intel', statement: 'VirusTotal reports IP 1.2.3.4 as suspicious. Not independently verified by SOCMind AI.', basis: [], reference_url: 'https://evil.example/x' },
      { type: 'hypothesis', statement: 'h', technique: 'T1071', technique_name: 'App Layer', confidence: 'low', basis: [] }],
  };
  t = html(h(Inc.Investigation, { inv: liveInv }));
  check('live intelligence is its own, attributed class', t, /Verified facts[\s\S]*VirusTotal intelligence — not independently verified \(2\)[\s\S]*Hypotheses/, 'Third-party engine verdicts', 'href="https://www.virustotal.com/gui/ip-address/185.220.101.5"');
  absent('live findings are not labelled mock', t, 'Mock threat intelligence');
  absent('non-VirusTotal reference links are dropped', t, 'evil.example');

  // Render each state into its own variable so every assertion inspects the panel it is about.
  const liveT = html(h(Alerts.AnalysisPanels, { alert: { id: 'X', status: 'ENRICHED', normalized_data: { enrichment: liveEnr } }, busy: false, onRun: noop, runError: null }));
  check('live panel is really rendered', liveT, 'Reputation (VirusTotal)', 'VirusTotal (live lookup)');
  absent('live state never shows the mock disclaimer or a mock header', liveT, 'LOCAL MOCK', 'Reputation (mock)', 'Local mock (unverified)');
  const unrecorded = { ...liveEnr, provider: undefined };
  const unrecordedT = html(h(Alerts.AnalysisPanels, { alert: { id: 'X', status: 'ENRICHED', normalized_data: { enrichment: unrecorded } }, busy: false, onRun: noop, runError: null }));
  check('live record without a provider is shown as unrecorded', unrecordedT, 'Live lookup, provider not recorded', 'Reputation (unrecorded)', 'does not name the provider');
  absent('live record without a provider is never credited to VirusTotal', unrecordedT, 'VirusTotal (live lookup)', 'Reputation (VirusTotal)', 'VirusTotal report', '>Lookup<');

  t = html(h(Report.default, { run }));
  check('run report', t, 'Triage Agent', 'Handled', 'SUCCESS', 'never executes');
  check('stored run matches', html(h(Report.default, { run: runs[0] })), runs[0].run_id);
  t = html(h(Agents.default, { refreshAlerts: noop }));
  check('agents shell', t, 'Run full pipeline');
  t = html(h(Audit.default, {}));
  check('audit page shell', t, 'Apply filters', 'Actor');
  t = html(h(Settings.default, {}));
  check('settings shell is read-only', t, 'Read-only');
  absent('settings has no fake controls', t, '<select', 'VERIFIED', 'Gemini', 'OpenAI');
  check('sidebar', html(h(Side.default, { activeTab: 'audit', setActiveTab: noop, counts: { alerts: 10, incidents: 2, audit: stats.audit_entries } })), 'Audit Log', '>10<');
  check('topbar', html(h(Top.default, { activeTab: 'audit', online: true })), 'Audit Trail', 'Backend API: Online');

  // ---- closing an alert (the same DELETE call the page sends after its confirmation), checked against the real backend
  const filterLib = await server.ssrLoadModule('/src/lib/alertFilters.js');
  const beforeClose = await api('/alerts?limit=100');
  const toClose = beforeClose.find((a) => a.status !== 'CLOSED');
  expect('there is an open alert to close', Boolean(toClose));
  if (toClose) {
    const closeResult = await api(`/alerts/${toClose.id}`, { method: 'DELETE' });
    expect('closing reports success and names the alert', closeResult.status === 'success' && closeResult.alert_id === toClose.id, JSON.stringify(closeResult));
    expect('closing reports which incidents were updated', Array.isArray(closeResult.incidents_updated));
    const afterClose = await api(`/alerts/${toClose.id}`);
    expect('the closed alert now reads back as CLOSED', afterClose.status === 'CLOSED', afterClose.status);
    const serverClosed = await api('/alerts?status=CLOSED&limit=100');
    expect('the server status filter lists the closed alert', serverClosed.some((a) => a.id === toClose.id) && serverClosed.every((a) => a.status === 'CLOSED'));
    const reloaded = await api('/alerts?limit=100');
    expect('a closed alert stays in the full list (it is not deleted)', reloaded.length === beforeClose.length && reloaded.some((a) => a.id === toClose.id));
    const clientClosed = filterLib.filterAlerts(reloaded, { status: 'CLOSED' }).map((a) => a.id).sort();
    expect('the page filter agrees with the server filter on live data', JSON.stringify(clientClosed) === JSON.stringify(serverClosed.map((a) => a.id).sort()), JSON.stringify(clientClosed));
    const clientOpen = filterLib.filterAlerts(reloaded, { status: 'NEW' });
    expect('the closed alert is not listed under another status', !clientOpen.some((a) => a.id === toClose.id));
    const statsAfter = await api('/stats');
    expect('statistics count the closed alert', (statsAfter.alerts.by_status.CLOSED || 0) >= 1, JSON.stringify(statsAfter.alerts.by_status));
    const auditRows = await api(`/audit-logs?action=ALERT_CLOSED&target_id=${toClose.id}`);
    expect('the close is in the audit log', auditRows.length >= 1, JSON.stringify(auditRows));
    let reclose = null;
    try { await api('/alerts/NOPE-NOT-AN-ALERT', { method: 'DELETE' }); } catch (e) { reclose = e; }
    expect('closing an unknown alert is a readable 404', reclose instanceof ApiError && reclose.status === 404, String(reclose));
  }

  await accountsModeCheck();
  await tokenModeCheck();
  // ---- api.js and Settings by authentication mode (header check, real module)
  await (async () => {
    const sent = [];
    const realFetch = globalThis.fetch;
    const hadWindow = Object.prototype.hasOwnProperty.call(globalThis, 'window');
    const previousWindow = globalThis.window;
    const store = new Map([['socmind.token', 'stale-browser-token-0123456789']]);
    globalThis.window = {
      sessionStorage: {
        getItem: (key) => (store.has(key) ? store.get(key) : null),
        setItem: (key, value) => store.set(key, value),
        removeItem: (key) => store.delete(key),
      },
      dispatchEvent: () => true,
    };
    globalThis.fetch = async (url, init = {}) => {
      sent.push({ url: String(url), headers: { ...(init.headers || {}) } });
      return realFetch(url, init);
    };
    let mod = null;
    try {
      mod = await server.ssrLoadModule('/src/api.js');
      const last = () => sent[sent.length - 1].headers;

      mod.setAuthMode('accounts');
      await mod.api('/config');
      expect('accounts mode sends no Authorization header, even with a stored bearer token', last().Authorization === undefined, JSON.stringify(last()));
      await mod.api('/incidents/NO-SUCH/recommend', { method: 'POST' }).catch(() => {});
      expect('accounts mode writes send no Authorization header either', last().Authorization === undefined, JSON.stringify(last()));

      mod.setAuthMode('token');
      await mod.api('/config');
      expect('token mode still sends its stored bearer token', last().Authorization === 'Bearer stale-browser-token-0123456789', JSON.stringify(last()));

      mod.setAuthMode('disabled');
      await mod.api('/config');
      expect('demo mode sends no Authorization header', last().Authorization === undefined);

      mod.setAuthMode('unknown');
      await mod.api('/config');
      expect('before the mode is known, nothing is sent', last().Authorization === undefined);
    } catch (err) {
      failures.push(`header-mode check crashed: ${err.stack || err}`);
    } finally {
      if (mod) mod.setAuthMode('unknown');
      globalThis.fetch = realFetch;
      if (hadWindow) globalThis.window = previousWindow;
      else delete globalThis.window;
    }

    // Settings, rendered per mode
    const SettingsPage = (await server.ssrLoadModule('/src/pages/Settings.jsx')).default;
    const accountOut = html(h(SettingsPage, { authMode: 'accounts', account: { authenticated: true, name: 'ana.analyst', role: 'analyst', idle_timeout_minutes: 30 } }));
    absent('Settings in accounts mode has no bearer-token input', accountOut, 'aria-label="Access token"', 'If the server runs in token mode');
    check('Settings in accounts mode shows the signed-in account', accountOut, 'Signed-in account', 'ana.analyst', 'Analyst');
    const tokenOut = html(h(SettingsPage, { authMode: 'token' }));
    check('Settings in token mode keeps the bearer-token input', tokenOut, 'aria-label="Access token"', 'If the server runs in token mode');
    const demoOut = html(h(SettingsPage, { authMode: 'disabled' }));
    check('Settings in demo mode keeps the demo wording', demoOut, 'In demo mode no token is needed');
    absent('Settings in demo mode has no account card', demoOut, 'Signed-in account');
    const pendingOut = html(h(SettingsPage, { authMode: 'unknown' }));
    absent('Settings claims nothing about access before the mode is known', pendingOut, 'aria-label="Access token"', 'Signed-in account');
  })();
} catch (err) {
  failures.push(`integration run crashed: ${err.stack || err}`);
} finally {
  await cleanup();
}

console.log(`integration checks passed: ${passed}`);
if (failures.length) {
  console.log('FAILURES:\n' + failures.map((f) => ' - ' + f).join('\n'));
  process.exit(1);
}
