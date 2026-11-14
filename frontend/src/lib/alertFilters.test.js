import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  CLOSE_CONFIRMATION, SEVERITY_FILTERS, STATUS_FILTERS, alertMatchesSearch, alertSeverity, alertStatus, filterAlerts,
  isAlertClosed, statusFilterLabel,
} from './alertFilters.js';

const src = (path) => readFileSync(new URL(path, import.meta.url), 'utf8').replace(/\r\n/g, '\n');

// A small, varied list: every status once or more, different severities, one alert with no status and one with raw_severity only.
const ALERTS = [
  { id: 'A-1', alert_title: 'Encoded PowerShell', source: 'CrowdStrike EDR', severity: 'CRITICAL', status: 'NEW', host: 'FIN-WKS-1', username: 'j.doe', source_ip: '203.0.113.30' },
  { id: 'A-2', alert_title: 'SSH brute force', source: 'Splunk', severity: 'HIGH', status: 'TRIAGED', host: 'LINUX-1', username: 'root', source_ip: '198.51.100.7' },
  { id: 'A-3', alert_title: 'Beacon to rare domain', source: 'Zeek', severity: 'HIGH', status: 'ENRICHED', host: 'FIN-WKS-1', username: 'j.doe' },
  { id: 'A-4', alert_title: 'Lateral movement', source: 'CrowdStrike EDR', severity: 'MEDIUM', status: 'CORRELATED', host: 'DC-1', username: 'svc-sql' },
  { id: 'A-5', alert_title: 'Credential dumping', source: 'CrowdStrike EDR', severity: 'CRITICAL', status: 'INVESTIGATING', host: 'DC-1', username: 'admin' },
  { id: 'A-6', alert_title: 'Old noisy alert', source: 'Splunk', severity: 'LOW', status: 'CLOSED', host: 'LINUX-1', username: 'root' },
  { id: 'A-7', alert_title: 'Raw severity only', source: 'Splunk', raw_severity: 'high', host: 'LINUX-2', username: 'bob' },   // no status
];
const ids = (rows) => rows.map((a) => a.id);

// ----------------------------------------------------------------------------------- the lists of values
test('the status filter offers exactly the statuses the backend sets, in lifecycle order', () => {
  assert.deepEqual(STATUS_FILTERS, ['ALL', 'NEW', 'TRIAGED', 'ENRICHED', 'CORRELATED', 'INVESTIGATING', 'CLOSED']);
});

test('the severity buttons are unchanged', () => {
  assert.deepEqual(SEVERITY_FILTERS, ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
});

test('status option labels are plain words', () => {
  assert.equal(statusFilterLabel('ALL'), 'Any status');
  assert.equal(statusFilterLabel('NEW'), 'New');
  assert.equal(statusFilterLabel('INVESTIGATING'), 'Investigating');
  assert.equal(statusFilterLabel('CLOSED'), 'Closed');
});

// ----------------------------------------------------------------------------------- reading an alert
test('severity falls back to raw_severity and is upper-case; a missing severity matches none', () => {
  assert.equal(alertSeverity({ severity: 'High' }), 'HIGH');
  assert.equal(alertSeverity({ raw_severity: 'critical' }), 'CRITICAL');
  assert.equal(alertSeverity({}), '');
  assert.equal(alertSeverity(null), '');
});

test('a missing status is NEW, as the table has always shown it, and statuses are upper-case', () => {
  assert.equal(alertStatus({}), 'NEW');
  assert.equal(alertStatus({ status: 'closed' }), 'CLOSED');
  assert.equal(alertStatus(undefined), 'NEW');
});

test('only a CLOSED alert is closed', () => {
  assert.equal(isAlertClosed({ status: 'CLOSED' }), true);
  assert.equal(isAlertClosed({ status: 'closed' }), true);
  for (const status of ['NEW', 'TRIAGED', 'ENRICHED', 'CORRELATED', 'INVESTIGATING', undefined]) {
    assert.equal(isAlertClosed({ status }), false, String(status));
  }
});

// ----------------------------------------------------------------------------------- filtering
test('with no filters, every alert is shown in its original order', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'ALL', status: 'ALL', search: '' })), ['A-1', 'A-2', 'A-3', 'A-4', 'A-5', 'A-6', 'A-7']);
  assert.deepEqual(ids(filterAlerts(ALERTS)), ['A-1', 'A-2', 'A-3', 'A-4', 'A-5', 'A-6', 'A-7']);
});

test('the severity filter works alone, including a severity that is only in raw_severity', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'HIGH' })), ['A-2', 'A-3', 'A-7']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'CRITICAL' })), ['A-1', 'A-5']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'INFO' })), []);
});

test('the status filter works alone, for every status', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'TRIAGED' })), ['A-2']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'ENRICHED' })), ['A-3']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'CORRELATED' })), ['A-4']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'INVESTIGATING' })), ['A-5']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'CLOSED' })), ['A-6']);
});

test('the NEW filter includes an alert whose status is missing, because the table shows it as NEW', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'NEW' })), ['A-1', 'A-7']);
});

test('closed alerts are listed under "any status" and hidden by every other status', () => {
  assert.ok(ids(filterAlerts(ALERTS, { status: 'ALL' })).includes('A-6'));
  for (const status of ['NEW', 'TRIAGED', 'ENRICHED', 'CORRELATED', 'INVESTIGATING']) {
    assert.ok(!ids(filterAlerts(ALERTS, { status })).includes('A-6'), status);
  }
});

test('search works alone and ignores case and surrounding spaces', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { search: '  crowdstrike ' })), ['A-1', 'A-4', 'A-5']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { search: '203.0.113.30' })), ['A-1']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { search: 'nothing-like-this' })), []);
});

test('severity, status and search must all match (AND)', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'HIGH', status: 'TRIAGED' })), ['A-2']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'CRITICAL', status: 'TRIAGED' })), [], 'critical alerts are not triaged here');
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'CRITICAL', search: 'crowdstrike' })), ['A-1', 'A-5']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'INVESTIGATING', search: 'dc-1' })), ['A-5']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'CRITICAL', status: 'NEW', search: 'fin-wks' })), ['A-1']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'CRITICAL', status: 'NEW', search: 'splunk' })), [], 'one failing condition empties the result');
});

test('filter values are not case sensitive', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'high', status: 'triaged' })), ['A-2']);
});

test('an unknown status or severity shows nothing instead of everything', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'REOPENED' })), []);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'URGENT' })), []);
});

test('filtering does not change the list it is given', () => {
  const before = JSON.stringify(ALERTS);
  filterAlerts(ALERTS, { severity: 'HIGH', status: 'ENRICHED', search: 'beacon' });
  assert.equal(JSON.stringify(ALERTS), before);
});

test('no list, or an empty one, gives an empty result', () => {
  assert.deepEqual(filterAlerts([], { status: 'NEW' }), []);
  assert.deepEqual(filterAlerts(undefined, { status: 'NEW' }), []);
});

// ----------------------------------------------------------------------------------- server-side search results
test('server matches replace the loaded list, and the local search is not applied to them', () => {
  const serverRows = [ALERTS[1], ALERTS[5]];                                          // the server matched these for some term
  assert.deepEqual(ids(filterAlerts(ALERTS, { search: 'a term that matches neither row locally' }, serverRows)), ['A-2', 'A-6']);
});

test('severity and status still narrow the server matches', () => {
  const serverRows = [ALERTS[1], ALERTS[2], ALERTS[5]];
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'HIGH' }, serverRows)), ['A-2', 'A-3']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'CLOSED' }, serverRows)), ['A-6']);
  assert.deepEqual(ids(filterAlerts(ALERTS, { severity: 'HIGH', status: 'ENRICHED' }, serverRows)), ['A-3']);
});

test('an empty server result means no matches, not a fall back to the loaded list', () => {
  assert.deepEqual(filterAlerts(ALERTS, { search: 'zzz' }, []), []);
});

test('with no server result (still pending, or the search failed) the loaded list is searched locally', () => {
  assert.deepEqual(ids(filterAlerts(ALERTS, { status: 'NEW', search: 'fin-wks' }, null)), ['A-1']);
});

// ----------------------------------------------------------------------------------- search helper (moved here, same behaviour)
test('alert search finds id, IP, title, source, host and user, ignoring case and spaces', () => {
  const alert = { id: 'ALT-2026-001', alert_title: 'Synthetic test', source: 'CrowdStrike EDR', host: 'FIN-WKS-042', username: 'j.doe', source_ip: '203.0.113.30' };
  assert.equal(alertMatchesSearch(alert, ' alt-2026-001 '), true);
  assert.equal(alertMatchesSearch(alert, '203.0.113.30'), true);
  for (const term of ['synthetic', 'crowdstrike', 'fin-wks', 'j.doe']) assert.equal(alertMatchesSearch(alert, term), true, term);
  assert.equal(alertMatchesSearch(alert, 'nothing-like-this'), false);
  assert.equal(alertMatchesSearch(alert, ''), true, 'an empty query matches every alert');
});

// ----------------------------------------------------------------------------------- closing an alert
test('the confirmation text says what closing does and that nothing is executed', () => {
  assert.equal(CLOSE_CONFIRMATION,
    'This marks the alert CLOSED and removes it from active incidents. It cannot be reopened. Nothing is executed.');
});

test('the page filters through the pure function with the server matches, and keeps the search export (wiring guard)', () => {
  const page = src('../pages/Alerts.jsx');
  assert.match(page, /filterAlerts\(alerts, \{ severity: filterSeverity, status: filterStatus, search: searchQuery \}, serverMatches\)/);
  assert.match(page, /export \{ alertMatchesSearch \};/);
  assert.match(page, /aria-label="Filter by alert status"/);
  assert.match(page, /STATUS_FILTERS\.map/);
  assert.doesNotMatch(page, /\['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'\]\.map/, 'the severity list is shared, not repeated');
});

test('the alert is closed only after the user confirms, and then the lists are reloaded (wiring guard)', () => {
  const page = src('../pages/Alerts.jsx');
  const deletes = page.match(/method: 'DELETE'/g) || [];
  assert.equal(deletes.length, 1, 'exactly one place sends DELETE');
  const handlerStart = page.indexOf('const handleConfirmClose = async () => {');
  const handlerEnd = page.indexOf('\n  };\n', handlerStart);
  const handler = page.slice(handlerStart, handlerEnd);
  assert.ok(handlerStart > 0 && handler.includes("api(`/alerts/${id}`, { method: 'DELETE' })"), 'DELETE is inside the confirm handler');
  assert.ok(handler.indexOf("method: 'DELETE'") < handler.indexOf('await refreshAlerts()'), 'alerts, incidents and statistics are reloaded after the close');
  assert.match(page, /onAsk=\{\(\) => \{ setCloseError\(null\); setCloseConfirming\(true\); \}\}/, 'the first click only opens the question');
  assert.match(page, /onConfirm=\{handleConfirmClose\}/);
  assert.match(page, /\{CLOSE_CONFIRMATION\}/);
});

test('the close button is disabled for a closed alert, and a failure is shown in an ErrorCard (wiring guard)', () => {
  const page = src('../pages/Alerts.jsx');
  assert.match(page, /disabled=\{closed \|\| busy\}/);
  assert.match(page, /<ErrorCard title="Could not close the alert" message=\{error\} \/>/);
  assert.match(page, /import \{ ActionButton, ErrorCard \} from '\.\.\/components\/StateCards';/);
  assert.match(page, /setCloseError\(err\.message\);/);
});
