import test from 'node:test';
import assert from 'node:assert/strict';
import {
  describeError, groupFindings, reputationKey, statusLabel, reviewState, formatUtc, summarizeRun, runBadgeKey, stageBadgeKey,
  simulationState, auditQuery, previewDetails, truncationNote,
  reputationSource, lookupStatusLabel, isRetryableLookup, detectionLabel, safeVirusTotalUrl, enrichmentNotices,
  intelSource, refreshedSelection, alertSearchPath, searchCapNote, fetchAlertSearch,
  recommendationView, reinvestigationNotice,
} from './view.js';

test('alertSearchPath trims the query, URL-encodes it and returns null for an empty query', () => {
  assert.equal(alertSearchPath('  ALT-2026-E1082F  '), '/alerts?search=ALT-2026-E1082F&limit=100');
  assert.equal(alertSearchPath('powershell -enc'), '/alerts?search=powershell%20-enc&limit=100');
  assert.equal(alertSearchPath('a&b=c#d+e%f'), '/alerts?search=a%26b%3Dc%23d%2Be%25f&limit=100');
  assert.equal(alertSearchPath('ALT-2026-E1082F', 25), '/alerts?search=ALT-2026-E1082F&limit=25');
  assert.equal(alertSearchPath(''), null);
  assert.equal(alertSearchPath('   '), null);
  assert.equal(alertSearchPath(undefined), null);
});

test('searchCapNote only speaks when a full page of matches came back', () => {
  assert.equal(searchCapNote(0), '');
  assert.equal(searchCapNote(99), '');
  assert.match(searchCapNote(100), /capped at 100/);
  assert.match(searchCapNote(250, 100), /capped at 100/);
});

test('fetchAlertSearch returns the trimmed term and the rows of a successful search', async () => {
  const calls = [];
  const rows = [{ id: 'ALT-2026-E1082F' }];
  const outcome = await fetchAlertSearch('  ALT-2026-E1082F  ', async (path) => { calls.push(path); return rows; });
  assert.deepEqual(outcome, { result: { term: 'ALT-2026-E1082F', rows }, error: null });
  assert.deepEqual(calls, ['/alerts?search=ALT-2026-E1082F&limit=100']);
});

test('fetchAlertSearch makes no request for an empty query', async () => {
  let requested = false;
  const outcome = await fetchAlertSearch('   ', async () => { requested = true; return []; });
  assert.deepEqual(outcome, { result: null, error: null });
  assert.equal(requested, false);
});

test('a failed repeat of a search returns no rows, so an earlier match is never shown as a current one', async () => {
  // Same query twice, as after the alert list reloads: the first request succeeds, the repeat fails.
  let failing = false;
  const request = async () => {
    if (failing) throw new Error('HTTP 503: upstream unavailable');
    return [{ id: 'ALT-2026-E1082F' }];
  };
  const first = await fetchAlertSearch('E1082F', request);
  assert.equal(first.result.rows.length, 1);

  failing = true;
  const repeat = await fetchAlertSearch('E1082F', request);
  assert.equal(repeat.result, null);                     // nothing from the earlier successful search
  assert.equal(repeat.error, 'HTTP 503: upstream unavailable');

  failing = false;
  const recovered = await fetchAlertSearch('E1082F', request);
  assert.equal(recovered.error, null);                   // a later success brings server matches back
  assert.equal(recovered.result.rows.length, 1);
});

test('a failed search reports a readable error even when the error has no message', async () => {
  const outcome = await fetchAlertSearch('x', async () => { throw new Error(''); });
  assert.deepEqual(outcome, { result: null, error: 'request failed' });
});

test('describeError uses string details, validation lists, then a generic message', () => {
  assert.equal(describeError(409, { detail: 'A decision is already recorded.' }), 'A decision is already recorded.');
  assert.equal(
    describeError(422, { detail: [{ loc: ['body', 'reviewer'], msg: 'String should have at least 1 character' }] }),
    'reviewer: String should have at least 1 character',
  );
  assert.equal(describeError(500, { message: 'An unexpected error occurred.' }), 'An unexpected error occurred.');
  assert.equal(describeError(502, null), 'Request failed (HTTP 502)');
});

test('groupFindings keeps verified facts, mock intelligence and hypotheses apart', () => {
  const g = groupFindings([{ type: 'verified' }, { type: 'hypothesis' }, { type: 'mock_intel' }, { type: 'verified' }, { type: 'other' }]);
  assert.deepEqual([g.verified.length, g.mock_intel.length, g.hypothesis.length], [2, 1, 1]);
  assert.deepEqual(groupFindings(undefined), { verified: [], mock_intel: [], external_intel: [], hypothesis: [] });
});

test('reputation colours: only MALICIOUS/SUSPICIOUS are alarming; CLEAN is never styled as success', () => {
  assert.equal(reputationKey('MALICIOUS'), 'critical');
  assert.equal(reputationKey('suspicious'), 'high');
  assert.equal(reputationKey('CLEAN'), 'low');
  assert.equal(reputationKey('UNKNOWN'), 'low');
  assert.equal(reputationKey(undefined), 'low');
});

test('statusLabel', () => {
  assert.equal(statusLabel('RESPONSE_PROPOSED'), 'Response proposed');
  assert.equal(statusLabel('SOMETHING_NEW'), 'Something new');
  assert.equal(statusLabel(null), 'Unknown');
});

test('reviewState only allows a decision on a fresh, undecided recommendation', () => {
  const inc = (over = {}, details = {}) => ({ human_approval_status: 'PENDING', details: { recommendations: [{}], recommendations_stale: false, ...details }, ...over });
  assert.equal(reviewState(inc()).canReview, true);
  assert.equal(reviewState({ human_approval_status: 'PENDING', details: null }).canReview, false);
  assert.match(reviewState(inc({}, { recommendations_stale: true })).reason, /changed/);
  assert.match(reviewState(inc({ human_approval_status: 'APPROVED' })).reason, /APPROVED/);
  assert.equal(reviewState(inc({}, { recommendations: [] })).canReview, false);
});

test('formatUtc never invents a time', () => {
  assert.equal(formatUtc('2026-09-03T08:14:00Z'), '2026-09-03 08:14:00 UTC');
  assert.equal(formatUtc(null), 'time unknown');
  assert.equal(formatUtc('garbage'), 'garbage');
});

test('run summaries and badge keys', () => {
  const run = { alerts_in_scope: 10, incidents_created: ['a', 'b'], stages: [{ status: 'success' }, { status: 'failed' }, { status: 'partial' }] };
  assert.equal(summarizeRun(run), '10 alert(s) in scope, 2 incident(s) created, 2 stage(s) with errors');
  assert.equal(summarizeRun({ alerts_in_scope: 0, incidents_created: [], stages: [] }), '0 alert(s) in scope, 0 incident(s) created');
  assert.equal(runBadgeKey('failure'), 'critical');
  assert.equal(runBadgeKey('partial'), 'high');
  assert.equal(stageBadgeKey('success'), 'success');
  assert.equal(stageBadgeKey('failed'), 'critical');
});


test('simulationState: only a fresh approval, only once, and never "executed"', () => {
  const inc = (status, details = {}) => ({ human_approval_status: status, details: { recommendations: [{}], ...details } });
  assert.equal(simulationState(inc('APPROVED')).canSimulate, true);
  assert.equal(simulationState(inc('PENDING')).canSimulate, false);
  assert.equal(simulationState(inc('REJECTED')).canSimulate, false);
  assert.match(simulationState(inc('APPROVED', { recommendations_stale: true })).reason, /out of date/);
  const done = simulationState(inc('APPROVED', { simulation: { status: 'SIMULATED' } }));
  assert.deepEqual([done.canSimulate, done.simulated], [false, true]);
  assert.equal(simulationState(null).canSimulate, false);
});

test('auditQuery builds only the filters that are set', () => {
  assert.equal(auditQuery(), '?limit=50&offset=0');
  assert.equal(auditQuery({ action: ' incident_approved ', target: 'INC-2026-001', limit: 20, offset: 40 }), '?action=INCIDENT_APPROVED&target_id=INC-2026-001&limit=20&offset=40');
  assert.equal(auditQuery({ actor: 'Triage Agent' }), '?actor=Triage+Agent&limit=50&offset=0');
});

test('previewDetails truncates and tolerates empty values', () => {
  assert.equal(previewDetails(null), '');
  assert.equal(previewDetails({ a: 1 }), '{"a":1}');
  assert.equal(previewDetails('x'.repeat(200), 10), 'xxxxxxxxx…');
});

test('truncationNote only speaks when the list is shorter than the total', () => {
  assert.equal(truncationNote(100, 130), 'Showing the first 100 of 130.');
  assert.equal(truncationNote(10, 10), '');
  assert.equal(truncationNote(10, undefined), '');
});

test('groupFindings keeps live VirusTotal findings apart from mock ones', () => {
  const g = groupFindings([{ type: 'mock_intel' }, { type: 'external_intel' }, { type: 'external_intel' }, { type: 'verified' }]);
  assert.deepEqual([g.mock_intel.length, g.external_intel.length, g.verified.length], [1, 2, 1]);
});

test('reputationSource names where reputations come from and defaults to mock', () => {
  assert.equal(reputationSource({ intel_mode: 'live', provider: 'VirusTotal' }), 'VirusTotal');
  // Changed deliberately: a live record that does not name its provider is no longer credited to VirusTotal.
  assert.equal(reputationSource({ intel_mode: 'live' }), 'unrecorded');
  assert.equal(reputationSource({ intel_mode: 'mock' }), 'mock');
  assert.equal(reputationSource({ intel_mode: 'unavailable' }), 'not looked up');
  assert.equal(reputationSource({}), 'mock');           // results stored before live mode existed carry no intel_mode
  assert.equal(reputationSource(undefined), 'mock');
});

test('lookup statuses are explained, and only transient ones are retryable', () => {
  assert.match(lookupStatusLabel('rate_limited'), /retry later/);
  assert.match(lookupStatusLabel('not_found'), /not evidence of safety/);
  assert.match(lookupStatusLabel('skipped_non_public_ip'), /not sent/);
  assert.equal(lookupStatusLabel('something_new'), 'something new');
  assert.equal(lookupStatusLabel(undefined), '');
  for (const s of ['rate_limited', 'budget_exceeded', 'timeout', 'error', 'circuit_open']) assert.equal(isRetryableLookup(s), true);
  for (const s of ['completed', 'not_found', 'auth_error', 'skipped_url', undefined]) assert.equal(isRetryableLookup(s), false);
});

test('detectionLabel', () => {
  assert.equal(detectionLabel({ malicious: 3, suspicious: 1, harmless: 60, undetected: 8, total: 72 }), '4/72 engines flagged');
  assert.equal(detectionLabel({ malicious: 0, total: 0 }), '');
  assert.equal(detectionLabel(null), '');
});

test('safeVirusTotalUrl only allows VirusTotal report pages', () => {
  assert.equal(safeVirusTotalUrl('https://www.virustotal.com/gui/ip-address/8.8.8.8'), 'https://www.virustotal.com/gui/ip-address/8.8.8.8');
  assert.equal(safeVirusTotalUrl('https://www.virustotal.com/gui/ip-address/2606:4700::1111'), 'https://www.virustotal.com/gui/ip-address/2606:4700::1111');
  for (const bad of ['javascript:alert(1)', 'http://www.virustotal.com/gui/file/ab', 'https://evil.example/gui/file/ab',
    'https://www.virustotal.com.evil.example/gui/file/ab', 'https://www.virustotal.com/gui/file/ab"onmouseover="x', null, undefined, 42]) {
    assert.equal(safeVirusTotalUrl(bad), null, String(bad));
  }
});

test('enrichmentNotices only speaks when something needs the analyst attention', () => {
  assert.deepEqual(enrichmentNotices({ intel_mode: 'mock' }), []);
  assert.deepEqual(enrichmentNotices({ intel_mode: 'live', incomplete: false }), []);
  assert.match(enrichmentNotices({ intel_mode: 'live', incomplete: true })[0], /could not be checked yet/);
  assert.match(enrichmentNotices({ intel_mode: 'mock', fallback_reason: 'VIRUSTOTAL_API_KEY is not configured' })[0], /VIRUSTOTAL_API_KEY/);
  assert.match(enrichmentNotices({ intel_mode: 'unavailable' })[0], /not checked/);
  assert.deepEqual(enrichmentNotices(null), []);
});

test('intelSource labels live only when the record says live AND names its provider', () => {
  const live = intelSource({ intel_mode: 'live', provider: 'VirusTotal', disclaimer: 'stored live text' });
  assert.equal(live.kind, 'live');
  assert.equal(live.live, true);
  assert.equal(live.label, 'VirusTotal (live lookup)');
  assert.equal(live.disclaimer, 'stored live text');
  assert.equal(live.verified, false);
  assert.equal(intelSource({ intel_mode: 'live', provider: 'VirusTotal' }).disclaimer.includes('VirusTotal'), true);
});

test('intelSource never labels live without a named provider', () => {
  for (const enrichment of [{ intel_mode: 'live' }, { intel_mode: 'live', provider: '' }, { intel_mode: 'live', provider: '   ' }, { intel_mode: 'live', provider: 42 }]) {
    const source = intelSource(enrichment);
    assert.equal(source.live, false, JSON.stringify(enrichment));
    assert.equal(source.kind, 'unrecorded');
    assert.match(source.disclaimer, /does not name the provider/);
  }
});

test('intelSource keeps the mock label and mock disclaimer, even when a provider name is present', () => {
  const stored = intelSource({ intel_mode: 'mock', disclaimer: 'Results come from LOCAL MOCK threat intelligence, not a verified live feed.' });
  assert.equal(stored.kind, 'mock');
  assert.equal(stored.live, false);
  assert.equal(stored.label, 'Local mock (unverified)');
  assert.match(stored.disclaimer, /LOCAL MOCK/);
  const missingText = intelSource({ intel_mode: 'mock' });
  assert.match(missingText.disclaimer, /LOCAL MOCK threat intelligence/);
  assert.match(missingText.disclaimer, /not mean the indicator is verified safe/);
  const contradictory = intelSource({ intel_mode: 'mock', provider: 'VirusTotal' });
  assert.equal(contradictory.live, false);
  assert.equal(contradictory.kind, 'mock');
});

test('intelSource treats records with no intel_mode as mock, but an unexplained provider as unrecorded', () => {
  assert.equal(intelSource({ summary: {} }).kind, 'mock');
  assert.equal(intelSource({ provider: 'VirusTotal' }).kind, 'unrecorded');
  assert.equal(intelSource({ provider: 'VirusTotal' }).live, false);
  assert.equal(intelSource(null), null);
  assert.equal(intelSource('garbage'), null);
});

test('intelSource: unavailable is "not looked up", never live', () => {
  const source = intelSource({ intel_mode: 'unavailable' });
  assert.equal(source.kind, 'unavailable');
  assert.equal(source.live, false);
  assert.equal(source.columnLabel, 'not looked up');
});

test('refreshedSelection replaces an open record with a newer copy from the list', () => {
  const opened = { id: 'A', updated_at: '2026-10-28T08:00:00.000001Z', normalized_data: { enrichment: { intel_mode: 'mock' } } };
  const listed = { id: 'A', updated_at: '2026-10-28T08:59:59.781145Z', normalized_data: { enrichment: { intel_mode: 'live', provider: 'VirusTotal' } } };
  assert.equal(refreshedSelection(opened, [listed]), listed);
});

test('refreshedSelection never lets an older list copy replace a newer open record', () => {
  const opened = { id: 'A', updated_at: '2026-10-28T09:00:00Z' };
  const olderList = { id: 'A', updated_at: '2026-10-28T08:00:00Z' };
  assert.equal(refreshedSelection(opened, [olderList]), opened);
});

test('refreshedSelection compares microseconds, so two writes within one millisecond are ordered correctly', () => {
  const opened = { id: 'A', updated_at: '2026-10-28T08:59:59.781145Z' };
  const listed = { id: 'A', updated_at: '2026-10-28T08:59:59.781146Z' };
  assert.equal(refreshedSelection(opened, [listed]), listed);
  assert.equal(refreshedSelection(listed, [opened]), listed);
});

test('refreshedSelection keeps the open record when the list does not contain it, or is missing', () => {
  const opened = { id: 'A', updated_at: '2026-10-28T08:00:00Z' };
  assert.equal(refreshedSelection(opened, [{ id: 'B', updated_at: '2030-01-01T00:00:00Z' }]), opened);
  assert.equal(refreshedSelection(opened, undefined), opened);
  assert.equal(refreshedSelection(null, [opened]), null);
});

test('refreshedSelection tolerates records without a readable timestamp', () => {
  const opened = { id: 'A', updated_at: 'not-a-date' };
  const listed = { id: 'A', updated_at: '2026-10-28T08:00:00Z' };
  assert.equal(refreshedSelection(opened, [listed]), listed);
  assert.equal(refreshedSelection({ id: 'A' }, [{ id: 'A' }]).id, 'A');
});

test('Alerts drawer re-syncs with the list it shows (wiring guard: the project has no DOM test runner)', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../pages/Alerts.jsx', import.meta.url), 'utf8');
  assert.match(source, /useEffect\(\(\) => \{\s*setSelectedAlert\(prev => \(prev \? refreshedSelection\(prev, alerts\) : prev\)\);\s*\}, \[alerts\]\);/);
  assert.match(source, /Reload from server/);
});

test('Alerts search takes its result from fetchAlertSearch on every outcome (wiring guard)', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../pages/Alerts.jsx', import.meta.url), 'utf8');
  assert.match(source, /const next = await fetchAlertSearch\(searchQuery, api\);/);
  assert.match(source, /setSearchResult\(next\.result\);/);
  assert.match(source, /setSearchError\(next\.error\);/);
  assert.doesNotMatch(source, /setSearchResult\(\{ term:/);   // the old write that kept earlier rows on failure is gone
});

// ---- superseded recommendations and the re-investigation warning ------------------------------------------------
test('recommendationView tells current proposals from superseded history', () => {
  assert.deepEqual(recommendationView(null), { kind: 'none', recommendations: [], reason: '', supersededAt: null });
  assert.equal(recommendationView({ recommendations: [] }).kind, 'none');
  assert.equal(recommendationView({ recommendations: [{ id: 'REC-1', status: 'PENDING' }] }).kind, 'current');
  const withdrawn = recommendationView({ recommendations: [
    { id: 'REC-1', status: 'SUPERSEDED', superseded_by: 'the analysis changed', superseded_at: '2026-10-28T09:00:00Z' },
    { id: 'REC-2', status: 'SUPERSEDED', superseded_by: 'the analysis changed', superseded_at: '2026-10-28T09:00:00Z' }] });
  assert.equal(withdrawn.kind, 'superseded');
  assert.equal(withdrawn.reason, 'the analysis changed');
  assert.equal(withdrawn.supersededAt, '2026-10-28T09:00:00Z');
});

test('recommendations left marked APPROVED by an older withdrawal read as superseded, not current', () => {
  const legacy = recommendationView({
    recommendations: [{ id: 'REC-1', status: 'APPROVED', simulation_status: 'SIMULATED', executed: false }],
    review_history: [{ superseded_at: '2026-10-28T09:00:00Z', superseded_by: 'threat intelligence changed' }],
  });
  assert.equal(legacy.kind, 'superseded');
  assert.equal(legacy.reason, 'threat intelligence changed');
  assert.equal(legacy.supersededAt, '2026-10-28T09:00:00Z');
  // A decision still in force keeps its own recommendations as current
  assert.equal(recommendationView({ review: { decision: 'APPROVED' }, recommendations: [{ id: 'REC-1', status: 'APPROVED' }] }).kind, 'current');
});

test('reinvestigationNotice warns about a recorded decision and stays silent for a pending incident', () => {
  assert.equal(reinvestigationNotice({ human_approval_status: 'PENDING', details: {} }), null);
  assert.equal(reinvestigationNotice(null), null);
  const approved = reinvestigationNotice({ human_approval_status: 'APPROVED',
    details: { review: { decision: 'APPROVED', reviewer: 'Analyst A' }, simulation: { simulated_by: 'Analyst B' } } });
  assert.match(approved, /approved decision by Analyst A and its simulation will be withdrawn/);
  assert.match(approved, /saved in the review history/);
  assert.match(approved, /superseded/);
  assert.match(reinvestigationNotice({ human_approval_status: 'REJECTED', details: {} }), /The rejected decision will be withdrawn/);
  const legacy = reinvestigationNotice({ human_approval_status: 'APPROVED', details: null });
  assert.match(legacy, /The approved decision will be withdrawn/);
  assert.doesNotMatch(legacy, /undefined/);
});

test('a superseded recommendation set cannot be approved, and the reason says why', () => {
  const state = reviewState({ human_approval_status: 'PENDING',
    details: { recommendations: [{ id: 'REC-1', status: 'SUPERSEDED' }], recommendations_stale: true } });
  assert.equal(state.canReview, false);
  assert.match(state.reason, /superseded when an earlier decision was withdrawn/);
});

test('Incidents page asks before re-investigating a decided incident (wiring guard)', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../pages/Incidents.jsx', import.meta.url), 'utf8');
  assert.match(source, /reinvestigationNotice\(inc\)/);
  assert.match(source, /export function ReinvestigateConfirm\(/);
  assert.match(source, /<ReinvestigateConfirm/);
  assert.match(source, /Withdraw decision and re-investigate/);
});

test('the stale notice takes the superseded state from recommendationView (wiring guard)', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../components/StaleNotice.jsx', import.meta.url), 'utf8');
  assert.match(source, /recommendationView\(details\)/);
});
