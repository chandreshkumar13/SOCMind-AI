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
    env: { ...process.env, DATABASE_URL: `sqlite:///${path.join(tmp, 'it.db').replace(/\\/g, '/')}`, PYTHONDONTWRITEBYTECODE: '1' },
  });
  child.stdout.on('data', (d) => { childLog += d; });
  child.stderr.on('data', (d) => { childLog += d; });
  child.on('error', (e) => { childLog += `spawn error: ${e.message}`; });

  let up = false;
  for (let i = 0; i < 80 && !up; i += 1) {
    try { up = (await fetch(`${base}/health`)).ok; } catch { await new Promise((r) => setTimeout(r, 250)); }
  }
  if (!up) throw new Error(`backend did not start on port ${port}. Is Python with the backend requirements available as "${python}"?\n${childLog.slice(-800)}`);

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
  expect('config is non-secret and simulation-only', cfg.execution_mode === 'simulation_only' && !JSON.stringify(cfg).toLowerCase().includes('api_key'));
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
  const Dash = await load('/src/pages/Dashboard.jsx');
  const Agents = await load('/src/pages/AgentActivity.jsx');
  const Audit = await load('/src/pages/AuditLog.jsx');
  const Settings = await load('/src/pages/Settings.jsx');
  const Report = await load('/src/components/PipelineRunReport.jsx');
  const Side = await load('/src/components/Sidebar.jsx');
  const Top = await load('/src/components/Topbar.jsx');
  const noop = () => {};

  let t = html(h(Inc.default, { incidents: await api('/incidents'), loading: false, error: null, refresh: noop, refreshAlerts: noop }));
  check('incident list', t, fin.id, 'FINANCE-WKS-042', 'Decision: APPROVED · simulated', 'Decision: APPROVED · not executed');
  absent('incident list has no demo data', t, 'INC-2026-089', 'Simulated Action');
  t = html(h(Inc.Investigation, { inv: pending.details.investigation }));
  check('investigation separates evidence classes', t, /Verified facts[\s\S]*Mock threat intelligence[\s\S]*Hypotheses/, 'Log source:', 'synthetic', 'UTC');
  t = html(h(Inc.Recommendations, { recs: simulated.details.recommendations, response: simulated.details.response }));
  check('recommendations', t, 'NOT EXECUTED', 'Simulation: SIMULATED', 'Risk if wrong', 'Rollback', 'Required approvals');
  absent('nothing is shown as executed', t, '>EXECUTED<');
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

  t = html(h(Dash.default, { alerts, incidents, stats, setActiveTab: noop }));
  check('dashboard', t, 'Alerts In Queue', 'Awaiting Human Review', '>10<');
  absent('dashboard has no fabricated metrics', t, 'MTTR', '-78%');
  t = html(h(Alerts.default, { alerts: alerts.slice(0, 3), loading: false, error: null, refreshAlerts: noop, seedSampleAlerts: noop, totalAlerts: 10 }));
  check('alerts list notes truncation', t, 'Showing the first 3 of 10.');
  const full = await api('/alerts/ALT-2026-001');
  t = html(h(Alerts.AnalysisPanels, { alert: full, busy: false, onRun: noop, runError: null }));
  check('alert analysis shows triage and mock enrichment', t, 'Score', 'MALICIOUS', 'LOCAL MOCK', 'incident');
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
