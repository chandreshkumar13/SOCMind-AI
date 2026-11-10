import { test } from 'node:test';
import assert from 'node:assert/strict';
import { beginRequest, createRequestGate, initialList, pageFailed, pageLoaded, receive, uniqueById } from './auditLoad.js';

const SIZE = 2;                               // a small page size keeps the examples readable
const entry = (id) => ({ id });

// Mirrors what the page does: start a request, mark the list as loading, then apply the answer when it arrives.
function start(gate, state) {
  return { id: gate.start(), state: beginRequest(state) };
}

test('the gate numbers requests and only the newest one is current', () => {
  const gate = createRequestGate();
  const first = gate.start();
  const second = gate.start();
  assert.ok(second > first);
  assert.equal(gate.isCurrent(first), false);
  assert.equal(gate.isCurrent(second), true);
});

test('a first page replaces the rows, a later page appends, and a short page means no more entries', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(1), entry(2)] }, SIZE);
  assert.deepEqual(state.rows.map((r) => r.id), [1, 2]);
  assert.equal(state.hasMore, true);
  assert.equal(state.loading, false);

  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: 2, page: [entry(3)] }, SIZE);
  assert.deepEqual(state.rows.map((r) => r.id), [1, 2, 3]);
  assert.equal(state.hasMore, false);
});

test('a stale page that arrives after a newer filter was applied is ignored, rows and loading flag alike', () => {
  const gate = createRequestGate();
  let state = initialList();
  const older = start(gate, state);                       // filter A
  const newer = start(gate, older.state);                 // filter B, applied after A
  // B answers first
  state = receive(gate, newer.id, newer.state, { offset: 0, page: [entry('B1')] }, SIZE);
  assert.deepEqual(state.rows.map((r) => r.id), ['B1']);
  assert.equal(state.loading, false);
  // A answers late: nothing changes
  const after = receive(gate, older.id, state, { offset: 0, page: [entry('A1'), entry('A2')] }, SIZE);
  assert.deepEqual(after, state);
});

test('a stale answer that arrives first does not clear the loading flag of the newer request', () => {
  const gate = createRequestGate();
  const older = start(gate, initialList());
  const newer = start(gate, older.state);
  assert.equal(newer.state.loading, true);
  const afterStale = receive(gate, older.id, newer.state, { offset: 0, page: [entry('A1')] }, SIZE);
  assert.equal(afterStale.loading, true, 'the newer request is still running');
  assert.deepEqual(afterStale.rows, []);
  const afterNewer = receive(gate, newer.id, afterStale, { offset: 0, page: [entry('B1')] }, SIZE);
  assert.equal(afterNewer.loading, false);
  assert.deepEqual(afterNewer.rows.map((r) => r.id), ['B1']);
});

test('a stale failure cannot put an error on, or clear the rows of, the newer results', () => {
  const gate = createRequestGate();
  const older = start(gate, initialList());
  const newer = start(gate, older.state);
  let state = receive(gate, newer.id, newer.state, { offset: 0, page: [entry('B1')] }, SIZE);
  const after = receive(gate, older.id, state, { offset: 0, error: 'old filter failed' }, SIZE);
  assert.equal(after.error, null);
  assert.deepEqual(after.rows.map((r) => r.id), ['B1']);
});

test('a refresh that starts while "load older" is pending makes the older page harmless', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(1), entry(2)] }, SIZE);
  const olderPage = start(gate, state);                   // load older entries, offset 2
  const refresh = start(gate, olderPage.state);           // refresh, offset 0
  state = receive(gate, refresh.id, refresh.state, { offset: 0, page: [entry(9), entry(8)] }, SIZE);
  const afterOld = receive(gate, olderPage.id, state, { offset: 2, page: [entry(3)] }, SIZE);
  assert.deepEqual(afterOld.rows.map((r) => r.id), [9, 8], 'the stale older page must not be appended to the refreshed list');
});

test('a failed first page clears rows from the previous filter and shows the error', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(1), entry(2)] }, SIZE);
  ({ id, state } = start(gate, state));                   // a new filter
  state = receive(gate, id, state, { offset: 0, error: 'Server unavailable' }, SIZE);
  assert.deepEqual(state.rows, [], 'rows of the previous filter must not be shown as results');
  assert.equal(state.error, 'Server unavailable');
  assert.equal(state.hasMore, false);
  assert.equal(state.loading, false);
});

test('a failed "load older" keeps the rows of the applied filter and keeps the error visible', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(1), entry(2)] }, SIZE);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: 2, error: 'timeout' }, SIZE);
  assert.deepEqual(state.rows.map((r) => r.id), [1, 2]);
  assert.equal(state.error, 'timeout');
  assert.equal(state.hasMore, true, 'more entries still exist, so the button stays');
});

test('beginning a request clears the old error and turns the loading flag on without touching the rows', () => {
  const failed = pageFailed(initialList(), 0, 'old error');
  const started = beginRequest(failed);
  assert.equal(started.error, null);
  assert.equal(started.loading, true);
  assert.deepEqual(started.rows, []);
});

test('pageLoaded decides whether more entries exist from the size of the page', () => {
  assert.equal(pageLoaded(initialList(), 0, [entry(1), entry(2)], 2).hasMore, true);
  assert.equal(pageLoaded(initialList(), 0, [entry(1)], 2).hasMore, false);
  assert.equal(pageLoaded(initialList(), 0, [], 2).hasMore, false);
});

test('the initial list is empty, loading and error-free, so the first render shows loading rather than an empty state', () => {
  assert.deepEqual(initialList(), { rows: [], hasMore: false, error: null, loading: true, nextOffset: 0 });
});

// A stand-in for GET /audit-logs: entries are given newest first and paged by offset, as the server does.
function serve(entriesNewestFirst) {
  return (offset, size) => entriesNewestFirst.slice(offset, offset + size);
}
const ids = (state) => state.rows.map((r) => r.id);

test('an entry repeated across two pages is kept once, in its original newest-first position', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(10), entry(9)] }, SIZE);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: 2, page: [entry(9), entry(8)] }, SIZE);   // 9 repeated at the boundary
  assert.deepEqual(ids(state), [10, 9, 8]);
});

test('the first page is de-duplicated too, and distinct entries are never dropped', () => {
  const state = pageLoaded(initialList(), 0, [entry(1), entry(1), entry(2), entry(3)], 4);
  assert.deepEqual(ids(state), [1, 2, 3]);
});

test('entries inserted while paging neither duplicate nor lose older entries, and each page starts where the server is', () => {
  const gate = createRequestGate();
  const before = serve([10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map(entry));
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: before(0, 3) }, 3);                 // 10, 9, 8
  // Entry 11 is written at the top before the next page is requested: everything older moves down by one.
  const after = serve([11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map(entry));
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: state.nextOffset, page: after(state.nextOffset, 3) }, 3);   // 8 is repeated
  assert.deepEqual(ids(state), [10, 9, 8, 7, 6]);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: state.nextOffset, page: after(state.nextOffset, 3) }, 3);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: state.nextOffset, page: after(state.nextOffset, 3) }, 3);
  assert.deepEqual(ids(state), [10, 9, 8, 7, 6, 5, 4, 3, 2, 1], 'every original entry exactly once, in order');
  assert.equal(state.hasMore, false);
});

test('the server offset follows what the server returned, not the number of rows shown', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(10), entry(9), entry(8)] }, 3);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: 3, page: [entry(8), entry(7), entry(6)] }, 3);
  assert.equal(ids(state).length, 5, 'one repeat was dropped');
  assert.equal(state.nextOffset, 6, 'the next request must start after the 6 entries the server has returned');
});

test('a page made only of repeats leaves the list unchanged but still moves the server offset forward', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(2), entry(1)] }, 2);
  const beforeRepeat = ids(state);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: 2, page: [entry(2), entry(1)] }, 2);
  assert.deepEqual(ids(state), beforeRepeat);
  assert.equal(state.nextOffset, 4, 'the next request moves on, so the paging cannot stall');
  assert.equal(state.hasMore, true);
});

test('entries without an id are never merged with each other or dropped', () => {
  const anon1 = { actor: 'a' };
  const anon2 = { actor: 'b' };
  assert.deepEqual(uniqueById([anon1, anon2, entry(1), entry(1)]), [anon1, anon2, entry(1)]);
  assert.equal(uniqueById([null, undefined, null]).length, 3);
});

test('uniqueById keeps the first copy and the original order, and leaves distinct ids alone', () => {
  const input = [entry(5), entry(4), entry(5), entry(3), entry(4), entry(2)];
  assert.deepEqual(uniqueById(input).map((r) => r.id), [5, 4, 3, 2]);
  assert.deepEqual(uniqueById([]), []);
  assert.deepEqual(uniqueById(null), []);
  // the input array is not changed
  assert.equal(input.length, 6);
});

test('a failed first page resets the server offset, so the next load starts from the top', () => {
  const gate = createRequestGate();
  let { id, state } = start(gate, initialList());
  state = receive(gate, id, state, { offset: 0, page: [entry(1), entry(2)] }, 2);
  assert.equal(state.nextOffset, 2);
  ({ id, state } = start(gate, state));
  state = receive(gate, id, state, { offset: 0, error: 'down' }, 2);
  assert.equal(state.nextOffset, 0);
});

test('the page keeps its sequencing and state through these functions (wiring guard)', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../pages/AuditLog.jsx', import.meta.url), 'utf8');
  assert.match(source, /setList\(beginRequest\)/);
  assert.match(source, /const id = gate\.start\(\)/);
  assert.match(source, /setList\(\(state\) => receive\(gate, id, state, \{ offset, page \}, PAGE\)\)/);
  assert.match(source, /setList\(\(state\) => receive\(gate, id, state, \{ offset, error: err\.message \}, PAGE\)\)/);
  assert.match(source, /load\(applied, nextOffset\)/);
  assert.doesNotMatch(source, /load\(applied, rows\.length\)/);
});
