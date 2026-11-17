import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  ACCOUNT_ROLES, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, USERNAME_RULE, canManageUsers, createAccountBody, disableBlockedReason,
  disableConfirmation, normaliseUsername, passwordChangeBody, passwordChangedMessage, passwordProblem, validateNewAccount,
  validatePasswordChange,
} from './accountForms.js';

// Reads a source file for the wiring checks. Line endings are normalised so the patterns below match on every platform.
const src = (path) => readFileSync(new URL(path, import.meta.url), 'utf8').replace(/\r\n/g, '\n');

const GOOD = 'a long enough passphrase';

// ----------------------------------------------------------------------------------- usernames and passwords
test('the roles offered are the three the backend knows', () => {
  assert.deepEqual(ACCOUNT_ROLES, ['viewer', 'analyst', 'approver']);
});

test('a username is trimmed and lower-cased, and anything the backend would refuse is refused here too', () => {
  assert.equal(normaliseUsername('  Ana.Analyst '), 'ana.analyst');
  assert.equal(normaliseUsername('a_b-c.d9'), 'a_b-c.d9');
  for (const bad of ['', 'ab', 'x'.repeat(65), 'has space', '.starts.with.dot', '-dash', 'semi;colon', 'ünïcode', null, undefined, 42]) {
    assert.equal(normaliseUsername(bad), null, String(bad));
  }
  assert.equal(normaliseUsername('x'.repeat(64)), 'x'.repeat(64));
});

test('a password needs 12 to 1024 characters and cannot be only spaces', () => {
  assert.equal(passwordProblem(GOOD), '');
  assert.equal(passwordProblem('a'.repeat(MIN_PASSWORD_LENGTH)), '');
  assert.match(passwordProblem('a'.repeat(MIN_PASSWORD_LENGTH - 1)), /at least 12 characters/);
  assert.equal(passwordProblem('a'.repeat(MAX_PASSWORD_LENGTH)), '');
  assert.match(passwordProblem('a'.repeat(MAX_PASSWORD_LENGTH + 1)), /at most 1024 characters/);
  assert.match(passwordProblem(' '.repeat(20)), /only spaces/);
  assert.equal(passwordProblem(''), 'Enter a password.');
  assert.equal(passwordProblem(undefined), 'Enter a password.');
});

test('characters are counted as the backend counts them, not as UTF-16 units', () => {
  const emoji = '🔒'.repeat(6);                          // 12 UTF-16 units, but only 6 characters
  assert.equal(emoji.length, 12);
  assert.match(passwordProblem(emoji), /at least 12 characters/);
  assert.equal(passwordProblem('🔒'.repeat(12)), '');
});

// ----------------------------------------------------------------------------------- the create-account form
test('a complete, matching create-account form is valid', () => {
  const result = validateNewAccount({ username: 'Ana.Analyst', role: 'analyst', password: GOOD, confirm: GOOD });
  assert.deepEqual(result, { valid: true, errors: {} });
});

test('the create-account form names every field that needs attention', () => {
  const result = validateNewAccount({ username: 'x', role: 'root', password: 'short', confirm: 'different' });
  assert.equal(result.valid, false);
  assert.equal(result.errors.username, USERNAME_RULE);
  assert.equal(result.errors.role, 'Choose a role.');
  assert.match(result.errors.password, /at least 12 characters/);
  assert.equal(result.errors.confirm, 'The two passwords do not match.');
  assert.deepEqual(Object.keys(validateNewAccount().errors).sort(), ['password', 'role', 'username'], 'an empty form lists the fields to fill in');
});

test('mismatched confirmation is caught even when the password itself is fine', () => {
  const result = validateNewAccount({ username: 'ana', role: 'viewer', password: GOOD, confirm: `${GOOD}!` });
  assert.deepEqual(Object.keys(result.errors), ['confirm']);
});

test('the create-account request carries the stored username and the password exactly as typed', () => {
  const body = createAccountBody({ username: '  Ana.Analyst ', role: 'analyst', password: ` ${GOOD} ` });
  assert.deepEqual(body, { username: 'ana.analyst', role: 'analyst', password: ` ${GOOD} ` });
  assert.deepEqual(Object.keys(body).sort(), ['password', 'role', 'username'], 'no confirmation field is sent');
});

// ----------------------------------------------------------------------------------- the change-password form
test('a complete change-password form is valid', () => {
  assert.deepEqual(validatePasswordChange({ current: 'the old one', next: GOOD, confirm: GOOD }), { valid: true, errors: {} });
});

test('the change-password form needs the current password, a good new one that differs, and a matching confirmation', () => {
  assert.equal(validatePasswordChange({ current: '', next: GOOD, confirm: GOOD }).errors.current, 'Enter your current password.');
  assert.match(validatePasswordChange({ current: 'x', next: 'short', confirm: 'short' }).errors.next, /at least 12 characters/);
  assert.equal(validatePasswordChange({ current: GOOD, next: GOOD, confirm: GOOD }).errors.next, 'The new password must be different from the current one.');
  assert.equal(validatePasswordChange({ current: 'x', next: GOOD, confirm: 'nope' }).errors.confirm, 'The two passwords do not match.');
  assert.equal(validatePasswordChange().valid, false);
});

test('the change-password request carries the two passwords exactly as typed and nothing else', () => {
  assert.deepEqual(passwordChangeBody({ current: ' old ', next: ' new new new new ' }), { current_password: ' old ', new_password: ' new new new new ' });
});

test('the message after a password change says how many other sessions were signed out', () => {
  assert.equal(passwordChangedMessage({ other_sessions_ended: 0 }), 'Password changed. You have no other open sessions.');
  assert.equal(passwordChangedMessage({ other_sessions_ended: 1 }), 'Password changed. 1 other session was signed out.');
  assert.equal(passwordChangedMessage({ other_sessions_ended: 3 }), 'Password changed. 3 other sessions were signed out.');
  assert.equal(passwordChangedMessage(null), 'Password changed. You have no other open sessions.');
});

// ----------------------------------------------------------------------------------- who sees what
test('only a signed-in approver in accounts mode is shown the user management controls', () => {
  assert.equal(canManageUsers({ authenticated: true, role: 'approver', name: 'boss' }, 'accounts'), true);
  assert.equal(canManageUsers({ authenticated: true, role: 'analyst' }, 'accounts'), false);
  assert.equal(canManageUsers({ authenticated: true, role: 'viewer' }, 'accounts'), false);
  assert.equal(canManageUsers({ authenticated: false, role: 'approver' }, 'accounts'), false);
  assert.equal(canManageUsers({ authenticated: true, role: 'approver' }, 'token'), false);
  assert.equal(canManageUsers({ authenticated: true, role: 'approver' }, 'disabled'), false);
  assert.equal(canManageUsers({ authenticated: true, role: 'approver' }, 'unknown'), false);
  assert.equal(canManageUsers(null, 'accounts'), false);
});

test('Disable is not offered for yourself or for the last active approver', () => {
  const users = [
    { username: 'boss.one', role: 'approver', is_active: true },
    { username: 'boss.two', role: 'approver', is_active: true },
    { username: 'ana', role: 'analyst', is_active: true },
    { username: 'old.timer', role: 'viewer', is_active: false },
  ];
  const me = { name: 'boss.one' };
  assert.equal(disableBlockedReason(users, users[0], me), 'You cannot disable your own account.');
  assert.equal(disableBlockedReason(users, users[1], me), '', 'another approver may be disabled while one other stays active');
  assert.equal(disableBlockedReason(users, users[2], me), '');
  assert.equal(disableBlockedReason(users, users[3], me), '', 'an account that is already disabled has nothing to block');
  const onlyOne = users.map((u) => (u.username === 'boss.two' ? { ...u, is_active: false } : u));
  assert.equal(disableBlockedReason(onlyOne, onlyOne[0], { name: 'someone.else' }), 'The last active approver cannot be disabled.');
  assert.equal(disableBlockedReason(onlyOne, onlyOne[2], me), '', 'a non-approver is never the last approver');
});

test('the confirmation names the account and says what disabling does', () => {
  const text = disableConfirmation('ana');
  assert.match(text, /^Disable ana\?/);
  assert.match(text, /open sessions end immediately/);
  assert.match(text, /enables the account again/);
});

// ----------------------------------------------------------------------------------- wiring: what the components do and never do
test('Settings shows the user table only through canManageUsers, and the password form to any signed-in account', () => {
  const settings = src('../pages/Settings.jsx');
  assert.match(settings, /canManageUsers\(account, authMode\) && <UserManagement account=\{account\} \/>/);
  assert.match(settings, /settingsAccessView\(authMode\) === 'account' && canChangePassword\(account\) && <ChangePasswordCard \/>/);
});

test('an account is disabled only after the confirmation step, never by the first click', () => {
  const page = src('../components/UserManagement.jsx');
  assert.match(page, /onAskDisable=\{\(name\) => \{ setRowError\(''\); setConfirming\(name\); \}\}/, 'the first click only asks');
  assert.match(page, /onConfirmDisable=\{\(name\) => change\(name, 'disable'\)\}/);
  assert.equal((page.match(/await api\(`\/auth\/users\/\$\{encodeURIComponent\(username\)\}\/\$\{action\}`/g) || []).length, 1, 'one place sends enable and disable');
  assert.match(page, /await api\(`\/auth\/users\/\$\{encodeURIComponent\(username\)\}\/\$\{action\}`, \{ method: 'POST' \}\)/);
  assert.match(page, /disableBlockedReason\(users, user, me\)/);
  assert.match(page, /disabled=\{Boolean\(blocked\) \|\| working\}/);
});

test('the forms validate before sending and clear the passwords as soon as the request is sent', () => {
  const users = src('../components/UserManagement.jsx');
  assert.ok(users.indexOf('validateNewAccount(form)') < users.indexOf("await api('/auth/users', { method: 'POST', body })"));
  assert.ok(users.indexOf("setForm({ ...EMPTY_FORM, role: form.role })") < users.indexOf("await api('/auth/users', { method: 'POST', body })"));
  const change = src('../components/ChangePasswordCard.jsx');
  assert.ok(change.indexOf('validatePasswordChange(form)') < change.indexOf("api('/auth/password', { method: 'POST', body })"));
  assert.ok(change.indexOf('setForm(EMPTY)') < change.indexOf("api('/auth/password', { method: 'POST', body })"));
});

test('passwords never go into browser storage, a URL or a log from these components', () => {
  for (const file of ['../components/UserManagement.jsx', '../components/ChangePasswordCard.jsx']) {
    const text = src(file);
    assert.doesNotMatch(text, /localStorage|sessionStorage|console\./, file);
    assert.match(text, /type="password"/, file);
  }
  assert.doesNotMatch(src('../components/UserManagement.jsx'), /\/auth\/users\?|password=/);
});
