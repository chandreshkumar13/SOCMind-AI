import { test } from 'node:test';
import assert from 'node:assert/strict';
import { closedNotice, computedFindingsByAlert, reviewState, simulationState } from './view.js';

const withRecs = { recommendations: [{ id: 'R-1', action: 'Isolate' }], human_approval_status: 'PENDING' };

test('a fully closed incident gets a read-only notice that names no decision', () => {
  const notice = closedNotice({ status: 'CLOSED', details: { closed_alerts: [{ alert_id: 'A-1' }, { alert_id: 'A-2' }] } });
  assert.equal(notice.level, 'closed');
  assert.deepEqual(notice.alertIds, ['A-1', 'A-2']);
  assert.match(notice.text, /closed because every alert/);
});

test('a partly closed incident says how many alerts left it and that the analysis is out of date', () => {
  const notice = closedNotice({ status: 'OPEN', details: { closed_alerts: [{ alert_id: 'A-9' }] } });
  assert.equal(notice.level, 'partial');
  assert.deepEqual(notice.alertIds, ['A-9']);
  assert.match(notice.text, /1 alert\(s\) were closed/);
  assert.match(notice.text, /out of date/);
});

test('an incident with no closed alerts gets no closed notice', () => {
  assert.equal(closedNotice({ status: 'OPEN', details: {} }), null);
  assert.equal(closedNotice(null), null);
});

test('closed incidents cannot be decided or simulated, even when they hold a pending recommendation', () => {
  const closed = { ...withRecs, status: 'CLOSED' };
  const review = reviewState(closed);
  assert.equal(review.canReview, false);
  assert.match(review.reason, /closed/);
  const sim = simulationState({ ...closed, human_approval_status: 'APPROVED', details: {} });
  assert.equal(sim.canSimulate, false);
  assert.match(sim.reason, /closed/);
});

test('an open incident with a pending recommendation can still be reviewed', () => {
  assert.equal(reviewState({ ...withRecs, status: 'RESPONSE_PROPOSED', details: { recommendations: withRecs.recommendations } }).canReview, true);
});

test('computed findings are taken only from triage findings marked computed, one row per alert with findings', () => {
  const rows = computedFindingsByAlert([
    {
      id: 'A-1', alert_title: 'PowerShell', normalized_data: {
        triage: {
          findings: [
            { type: 'computed', statement: 'Encoded PowerShell command line' },
            { type: 'verified', statement: 'should not appear here' },
          ],
        },
      },
    },
    { id: 'A-2', alert_title: 'Quiet', normalized_data: { triage: { findings: [] } } },
    { id: 'A-3', alert_title: 'No triage yet', normalized_data: null },
  ]);
  assert.deepEqual(rows, [{ id: 'A-1', title: 'PowerShell', statements: ['Encoded PowerShell command line'] }]);
});

test('computed findings helper tolerates an empty or missing list', () => {
  assert.deepEqual(computedFindingsByAlert(undefined), []);
  assert.deepEqual(computedFindingsByAlert([]), []);
});
