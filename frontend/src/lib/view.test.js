import test from 'node:test';
import assert from 'node:assert/strict';
import {
  describeError, groupFindings, reputationKey, statusLabel, reviewState, formatUtc, summarizeRun, runBadgeKey, stageBadgeKey,
  simulationState, auditQuery, previewDetails, truncationNote,
} from './view.js';

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
  assert.deepEqual(groupFindings(undefined), { verified: [], mock_intel: [], hypothesis: [] });
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
