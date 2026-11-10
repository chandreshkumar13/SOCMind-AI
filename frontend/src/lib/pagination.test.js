import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendPage, loadMoreNote } from './view.js';

test('appendPage adds the next page after the loaded records, in order', () => {
  const merged = appendPage([{ id: 'A' }, { id: 'B' }], [{ id: 'C' }, { id: 'D' }]);
  assert.deepEqual(merged.map((r) => r.id), ['A', 'B', 'C', 'D']);
});

test('appendPage keeps the first copy when a record shifts onto two pages', () => {
  const merged = appendPage([{ id: 'A', status: 'NEW' }, { id: 'B' }], [{ id: 'B' }, { id: 'C' }]);
  assert.deepEqual(merged.map((r) => r.id), ['A', 'B', 'C']);
  assert.equal(merged[0].status, 'NEW');
});

test('appendPage tolerates an empty or missing page', () => {
  assert.deepEqual(appendPage([{ id: 'A' }], []).map((r) => r.id), ['A']);
  assert.deepEqual(appendPage([{ id: 'A' }], undefined).map((r) => r.id), ['A']);
});

test('loadMoreNote says how many are shown when more exist on the server', () => {
  assert.equal(loadMoreNote(100, 240, 'alerts'), 'Showing 100 of 240 alerts.');
});

test('loadMoreNote is empty once everything is loaded, or when the total is unknown', () => {
  assert.equal(loadMoreNote(240, 240, 'alerts'), '');
  assert.equal(loadMoreNote(10, null, 'alerts'), '');
  assert.equal(loadMoreNote(10, undefined, 'alerts'), '');
});
