import { test } from 'node:test';
import assert from 'node:assert/strict';
import { authHeaders, describeAccessError } from './view.js';

test('authHeaders sends the token as a bearer header and nothing when no token is set', () => {
  assert.deepEqual(authHeaders('  abc123  '), { Authorization: 'Bearer abc123' });
  assert.deepEqual(authHeaders(''), {});
  assert.deepEqual(authHeaders('   '), {});
  assert.deepEqual(authHeaders(null), {});
});

test('a 401 explains that a token is needed, and a 403 names the missing permission without echoing a token', () => {
  assert.match(describeAccessError(401), /sign in|token/i);
  assert.match(describeAccessError(403), /role|permission/i);
  assert.equal(describeAccessError(200), '');
});
