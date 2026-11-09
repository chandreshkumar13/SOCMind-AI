import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_CRITERIA, activeIncidents, filterAndSortIncidents, isDefaultView, matchesFilters, matchesSearch,
  searchableFields, severityRank, shownSummary, timeValue,
} from './incidentFilters.js';

const base = {
  id: 'INC-2026-001', title: 'Outbound Connection to Known Malicious C2 IP on FINANCE-WKS-042', severity: 'CRITICAL',
  status: 'RESPONSE_PROPOSED', human_approval_status: 'PENDING', created_at: '2026-10-22T10:00:00.000000Z',
  correlated_alert_ids: ['ALT-1', 'ALT-2', 'ALT-3'], ai_summary: 'Encoded PowerShell beaconed to 185.220.101.5.',
  details: { investigation: { entities: { hosts: ['FINANCE-WKS-042'], users: ['j.doe'], ips: ['185.220.101.5'] } } },
};
const make = (over = {}) => ({ ...base, ...over });
const ids = (list) => list.map((i) => i.id);

// ------------------------------------------------------------------ search
test('search is case-insensitive and ignores leading and trailing spaces', () => {
  const finance = make();
  assert.equal(matchesSearch(finance, 'finance-wks'), true);
  assert.equal(matchesSearch(finance, '  FINANCE-WKS-042  '), true);
  assert.equal(matchesSearch(finance, '   '), true);
  assert.equal(matchesSearch(finance, ''), true);
  assert.equal(matchesSearch(finance, 'dc-primary'), false);
});

test('search covers the id, title, AI summary and the hosts, users and IPs of the investigation entities', () => {
  const inc = make({ id: 'INC-2026-777' });
  for (const term of ['INC-2026-777', 'c2 ip', 'beaconed', 'finance-wks', 'j.doe', '185.220.101.5']) {
    assert.equal(matchesSearch(inc, term), true, term);
  }
  assert.equal(matchesSearch(inc, 'nothing-like-this'), false);
});

test('search never matches across two fields', () => {
  const inc = make({ title: 'Alpha', ai_summary: 'Beta', details: {} });
  assert.equal(matchesSearch(inc, 'alphabeta'), false);
  assert.equal(matchesSearch(inc, 'a b'), false);
});

test('search tolerates missing or malformed entity data', () => {
  const messy = make({ details: { investigation: { entities: { hosts: 'not-a-list', users: [null, 42, 'svc-backup'], ips: undefined } } } });
  assert.equal(searchableFields(messy).at(-1), 'svc-backup');   // non-strings and non-lists are ignored
  assert.equal(matchesSearch(messy, 'svc-backup'), true);
  assert.equal(matchesSearch(make({ details: null }), 'finance'), true);   // the title still matches
  assert.equal(matchesSearch(make({ details: null, title: null, ai_summary: null }), 'finance'), false);
});

// ------------------------------------------------------------------ filters
test('each filter works on its own', () => {
  const approved = make({ human_approval_status: 'APPROVED', status: 'RESPONSE_APPROVED' });
  assert.equal(matchesFilters(make(), { severity: 'CRITICAL' }), true);
  assert.equal(matchesFilters(make(), { severity: 'LOW' }), false);
  assert.equal(matchesFilters(approved, { approval: 'APPROVED' }), true);
  assert.equal(matchesFilters(approved, { approval: 'PENDING' }), false);
  assert.equal(matchesFilters(approved, { status: 'RESPONSE_APPROVED' }), true);
  assert.equal(matchesFilters(approved, { status: 'OPEN' }), false);
});

test('ALL switches a filter off, and filters combine with AND', () => {
  const inc = make({ severity: 'HIGH', human_approval_status: 'PENDING', status: 'RESPONSE_PROPOSED' });
  assert.equal(matchesFilters(inc, { severity: 'ALL', approval: 'ALL', status: 'ALL' }), true);
  assert.equal(matchesFilters(inc, { severity: 'HIGH', approval: 'PENDING' }), true);
  assert.equal(matchesFilters(inc, { severity: 'HIGH', approval: 'APPROVED' }), false);
  assert.equal(matchesFilters(inc, { severity: 'HIGH', search: 'finance', status: 'OPEN' }), false);
});

test('filter values are matched case-insensitively', () => {
  assert.equal(matchesFilters(make(), { severity: 'critical', approval: 'pending' }), true);
});

test('MERGED incidents are never listed or counted', () => {
  const merged = make({ id: 'INC-M', status: 'MERGED' });
  const list = [make({ id: 'INC-A' }), merged, make({ id: 'INC-B' })];
  assert.deepEqual(ids(filterAndSortIncidents(list, {})), ['INC-A', 'INC-B']);
  assert.equal(activeIncidents(list).length, 2);
  assert.deepEqual(ids(filterAndSortIncidents(list, { status: 'MERGED' })), []);
});

// ------------------------------------------------------------------ sorting
test('newest first is the default and uses the timestamp, including microseconds', () => {
  const list = [
    make({ id: 'A', created_at: '2026-10-22T10:00:00.000100Z' }),
    make({ id: 'B', created_at: '2026-10-22T10:00:00.000900Z' }),
    make({ id: 'C', created_at: '2026-10-21T09:00:00Z' }),
  ];
  assert.deepEqual(ids(filterAndSortIncidents(list)), ['B', 'A', 'C']);
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'newest' })), ['B', 'A', 'C']);
});

test('oldest first reverses the time order', () => {
  const list = [make({ id: 'A', created_at: '2026-10-22T10:00:00Z' }), make({ id: 'B', created_at: '2026-10-21T10:00:00Z' })];
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'oldest' })), ['B', 'A']);
});

test('missing or unreadable times sort last in both time orders', () => {
  const list = [make({ id: 'NO-TIME', created_at: null }), make({ id: 'OLD', created_at: '2026-01-01T00:00:00Z' }),
    make({ id: 'BAD', created_at: '2026-13-45' }), make({ id: 'NEW', created_at: '2026-10-22T00:00:00Z' })];
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'newest' })), ['NEW', 'OLD', 'BAD', 'NO-TIME']);
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'oldest' })), ['OLD', 'NEW', 'BAD', 'NO-TIME']);
});

test('highest severity first uses CRITICAL > HIGH > MEDIUM > LOW > INFO, and unknown values sort last', () => {
  const list = [make({ id: 'I', severity: 'INFO' }), make({ id: 'W', severity: 'weird' }), make({ id: 'C', severity: 'CRITICAL' }),
    make({ id: 'L', severity: 'LOW' }), make({ id: 'H', severity: 'high' }), make({ id: 'M', severity: 'MEDIUM' })];
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'severity' })), ['C', 'H', 'M', 'L', 'I', 'W']);
  assert.equal(severityRank('CRITICAL'), 0);
  assert.equal(severityRank(undefined), 5);
});

test('most alerts first counts correlated alerts, and a missing list counts as zero', () => {
  const list = [make({ id: 'TWO', correlated_alert_ids: ['a', 'b'] }), make({ id: 'NONE', correlated_alert_ids: undefined }),
    make({ id: 'FIVE', correlated_alert_ids: ['a', 'b', 'c', 'd', 'e'] })];
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'alerts' })), ['FIVE', 'TWO', 'NONE']);
});

test('ties keep a deterministic order by incident id, whatever the input order', () => {
  const same = [make({ id: 'INC-3' }), make({ id: 'INC-1' }), make({ id: 'INC-2' })];
  for (const sort of ['newest', 'oldest', 'severity', 'alerts']) {
    assert.deepEqual(ids(filterAndSortIncidents(same, { sort })), ['INC-1', 'INC-2', 'INC-3'], sort);
    assert.deepEqual(ids(filterAndSortIncidents([...same].reverse(), { sort })), ['INC-1', 'INC-2', 'INC-3'], sort);
  }
});

test('an unknown sort name falls back to newest first', () => {
  const list = [make({ id: 'OLD', created_at: '2026-01-01T00:00:00Z' }), make({ id: 'NEW', created_at: '2026-10-22T00:00:00Z' })];
  assert.deepEqual(ids(filterAndSortIncidents(list, { sort: 'bogus' })), ['NEW', 'OLD']);
});

// ------------------------------------------------------------------ the whole pipeline of the list
test('the input array is never changed', () => {
  const list = [make({ id: 'B', severity: 'LOW' }), make({ id: 'A', severity: 'CRITICAL' })];
  const snapshot = JSON.stringify(list);
  filterAndSortIncidents(list, { sort: 'severity', search: 'finance' });
  assert.equal(JSON.stringify(list), snapshot);
});

test('an empty or missing list gives an empty result', () => {
  assert.deepEqual(filterAndSortIncidents([], {}), []);
  assert.deepEqual(filterAndSortIncidents(undefined, { search: 'x' }), []);
  assert.deepEqual(filterAndSortIncidents(null), []);
});

test('filters and sorting combine', () => {
  const list = [
    make({ id: 'INC-1', severity: 'HIGH', human_approval_status: 'PENDING', created_at: '2026-10-22T09:00:00Z' }),
    make({ id: 'INC-2', severity: 'CRITICAL', human_approval_status: 'PENDING', created_at: '2026-10-22T08:00:00Z' }),
    make({ id: 'INC-3', severity: 'CRITICAL', human_approval_status: 'APPROVED', status: 'RESPONSE_APPROVED', created_at: '2026-10-22T10:00:00Z' }),
    make({ id: 'INC-4', severity: 'CRITICAL', human_approval_status: 'PENDING', status: 'MERGED' }),
  ];
  assert.deepEqual(ids(filterAndSortIncidents(list, { approval: 'PENDING', sort: 'severity' })), ['INC-2', 'INC-1']);
  assert.deepEqual(ids(filterAndSortIncidents(list, { severity: 'CRITICAL', sort: 'oldest' })), ['INC-2', 'INC-3']);
});

// ------------------------------------------------------------------ view state and text
test('the default view is detected, so "Clear filters" appears only when something differs', () => {
  assert.equal(isDefaultView(DEFAULT_CRITERIA), true);
  assert.equal(isDefaultView({}), true);
  assert.equal(isDefaultView({ search: '   ' }), true);
  assert.equal(isDefaultView({ search: 'finance' }), false);
  assert.equal(isDefaultView({ severity: 'HIGH' }), false);
  assert.equal(isDefaultView({ approval: 'PENDING' }), false);
  assert.equal(isDefaultView({ status: 'OPEN' }), false);
  assert.equal(isDefaultView({ sort: 'alerts' }), false);
});

test('the summary line counts shown against the non-merged total', () => {
  assert.equal(shownSummary(3, 12), 'Showing 3 of 12 incidents');
  assert.equal(shownSummary(1, 1), 'Showing 1 of 1 incident');
  assert.equal(shownSummary(0, 0), 'Showing 0 of 0 incidents');
});

test('timeValue reads UTC timestamps to the microsecond and rejects anything else', () => {
  assert.equal(timeValue('2026-10-22T14:18:05.601364Z'), Date.parse('2026-10-22T14:18:05Z') * 1000 + 601364);
  assert.equal(timeValue('2026-10-22T14:18:05Z'), Date.parse('2026-10-22T14:18:05Z') * 1000);
  assert.equal(timeValue('2026-10-22T14:18:05+05:30'), null);      // not UTC: refused rather than guessed
  assert.equal(timeValue(''), null);
  assert.equal(timeValue(undefined), null);
});
