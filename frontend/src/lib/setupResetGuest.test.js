// First-run setup, an approver's password reset, and the optional read-only guest: the pure helpers and the wiring of the components.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  FORGOT_PASSWORD_NOTE, USERNAME_RULE, canChangePassword, canManageUsers, passwordResetBody, passwordResetMessage, resetBlockedReason,
  resetConfirmation, setupBody, validateFirstAdmin, validatePasswordReset,
} from './accountForms.js';
import { countsAsActivity, guestAllowed, identityLabel, isGuest, setupRequired, signedOutAfter, signInRequired } from './session.js';

// Reads a source file for the wiring checks. Line endings are normalised so the patterns below match on every platform.
const src = (path) => readFileSync(new URL(path, import.meta.url), 'utf8').replace(/\r\n/g, '\n');

const GOOD = 'a long enough passphrase';

// ----------------------------------------------------------------------------------- what the server's status means for the page
test('setup is offered only in accounts mode while the server says no account exists', () => {
  assert.equal(setupRequired({ mode: 'accounts', sign_in: true, setup_required: true }), true);
  assert.equal(setupRequired({ mode: 'accounts', sign_in: true, setup_required: false }), false);
  assert.equal(setupRequired({ mode: 'accounts', sign_in: true }), false, 'an older server that does not say');
  assert.equal(setupRequired({ mode: 'token', sign_in: false, setup_required: true }), false, 'never outside accounts mode');
  assert.equal(setupRequired(null), false);
});

test('the guest button is offered only when the server allows guests in accounts mode, and never beside the setup form', () => {
  assert.equal(guestAllowed({ mode: 'accounts', sign_in: true, guest_allowed: true, setup_required: false }), true);
  assert.equal(guestAllowed({ mode: 'accounts', sign_in: true, guest_allowed: true }), true);
  assert.equal(guestAllowed({ mode: 'accounts', sign_in: true, guest_allowed: false }), false);
  assert.equal(guestAllowed({ mode: 'accounts', sign_in: true }), false, 'off unless the server says so');
  assert.equal(guestAllowed({ mode: 'accounts', sign_in: true, guest_allowed: true, setup_required: true }), false);
  assert.equal(guestAllowed({ mode: 'disabled', sign_in: false, guest_allowed: true }), false);
  assert.equal(guestAllowed(undefined), false);
});

test('a guest is recognised only from what the server returned, and the top bar says so', () => {
  assert.equal(isGuest({ authenticated: true, name: 'guest', role: 'viewer', guest: true }), true);
  assert.equal(isGuest({ authenticated: true, name: 'guest', role: 'viewer' }), false, 'the name alone does not make a guest');
  assert.equal(isGuest(null), false);
  assert.deepEqual(identityLabel({ authenticated: true, name: 'guest', role: 'viewer', guest: true }, 'accounts'), { title: 'Guest (read-only)', subtitle: '' });
  assert.deepEqual(identityLabel({ authenticated: true, name: 'ana', role: 'analyst' }, 'accounts'), { title: 'ana', subtitle: 'Analyst' });
});

test('a 401 from setup, guest or a password change is an ordinary answer, not "the session ended"', () => {
  for (const path of ['/auth/setup', '/auth/guest', '/auth/login', '/auth/password']) {
    assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path }), false, path);
  }
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/auth/users/ana/password' }), true, 'a reset 401 is a lost session');
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/alerts' }), true);
});

test('setup and guest answers do not restart the idle clock, a reset does', () => {
  assert.equal(countsAsActivity({ mode: 'accounts', status: 200, path: '/auth/setup' }), false);
  assert.equal(countsAsActivity({ mode: 'accounts', status: 200, path: '/auth/guest' }), false);
  assert.equal(countsAsActivity({ mode: 'accounts', status: 200, path: '/auth/users/ana/password' }), true);
});

test('the page still treats accounts mode as the only one with sign-in, whatever the other fields say', () => {
  assert.equal(signInRequired({ mode: 'token', sign_in: false, setup_required: true, guest_allowed: true }), false);
});

// ----------------------------------------------------------------------------------- the first-run form
test('a complete first-run form is valid and has no role to choose', () => {
  assert.deepEqual(validateFirstAdmin({ username: 'First.Admin', password: GOOD, confirm: GOOD }), { valid: true, errors: {} });
  assert.equal('role' in validateFirstAdmin().errors, false);
});

test('the first-run form names every field that needs attention', () => {
  const result = validateFirstAdmin({ username: 'x', password: 'short', confirm: 'different' });
  assert.equal(result.valid, false);
  assert.equal(result.errors.username, USERNAME_RULE);
  assert.match(result.errors.password, /at least 12 characters/);
  assert.equal(result.errors.confirm, 'The two passwords do not match.');
  assert.deepEqual(Object.keys(validateFirstAdmin().errors).sort(), ['password', 'username']);
  assert.deepEqual(Object.keys(validateFirstAdmin({ username: 'ana', password: GOOD, confirm: `${GOOD}!` }).errors), ['confirm']);
});

test('the setup request carries the stored username and both passwords exactly as typed, and no role', () => {
  const body = setupBody({ username: '  First.Admin ', password: ` ${GOOD} `, confirm: ` ${GOOD} ` });
  assert.deepEqual(body, { username: 'first.admin', password: ` ${GOOD} `, confirm: ` ${GOOD} ` });
  assert.equal('role' in body, false, 'the server decides: the first account is an approver');
});

// ----------------------------------------------------------------------------------- the approver's reset
test('a reset needs a good new password typed twice', () => {
  assert.deepEqual(validatePasswordReset({ next: GOOD, confirm: GOOD }), { valid: true, errors: {} });
  assert.match(validatePasswordReset({ next: 'short', confirm: 'short' }).errors.next, /at least 12 characters/);
  assert.equal(validatePasswordReset({ next: GOOD, confirm: 'nope' }).errors.confirm, 'The two passwords do not match.');
  assert.equal(validatePasswordReset().valid, false);
});

test('the reset request carries only the new password, exactly as typed', () => {
  assert.deepEqual(passwordResetBody({ next: ` ${GOOD} `, confirm: 'ignored' }), { new_password: ` ${GOOD} ` });
});

test('Reset password is not offered for your own account, where Change password applies', () => {
  const me = { name: 'boss.one' };
  assert.equal(resetBlockedReason({ username: 'boss.one' }, me), 'Use Change password for your own account.');
  assert.equal(resetBlockedReason({ username: 'ana' }, me), '');
  assert.equal(resetBlockedReason({ username: 'ana', is_active: false }, me), '', 'a disabled account can be reset');
  assert.equal(resetBlockedReason({ username: 'ana' }, null), '');
});

test('the reset confirmation names the account and says what a reset does', () => {
  const text = resetConfirmation('ana');
  assert.match(text, /^Set a new password for ana\?/);
  assert.match(text, /Every open session of ana ends at once/);
  assert.match(text, /old password stops working/);
});

test('the message after a reset says how many sessions ended and never contains a password', () => {
  assert.match(passwordResetMessage('ana', { sessions_ended: 0 }), /^Password reset for "ana"\. They had no open sessions\./);
  assert.match(passwordResetMessage('ana', { sessions_ended: 1 }), /1 open session ended\./);
  assert.match(passwordResetMessage('ana', { sessions_ended: 3 }), /3 open sessions ended\./);
  assert.match(passwordResetMessage('ana', null), /no open sessions/);
  assert.match(passwordResetMessage('ana', { sessions_ended: 2 }), /Give them the new password in person; it is not shown again\./);
});

test('the sign-in page note says to ask an approver', () => {
  assert.equal(FORGOT_PASSWORD_NOTE, 'Forgot your password? Ask an approver to reset it.');
});

// ----------------------------------------------------------------------------------- who sees what
test('a guest has no password to change and manages no accounts', () => {
  const guest = { authenticated: true, name: 'guest', role: 'viewer', guest: true };
  assert.equal(canChangePassword(guest), false);
  assert.equal(canChangePassword({ authenticated: true, name: 'ana', role: 'analyst' }), true);
  assert.equal(canChangePassword({ authenticated: false }), false);
  assert.equal(canChangePassword(null), false);
  assert.equal(canManageUsers({ ...guest, role: 'approver' }, 'accounts'), false, 'even a record that claimed approver');
});

// ----------------------------------------------------------------------------------- wiring: what the components do and never do
test('the sign-in page shows the guest button only through the server flag, and always shows the reset note (wiring guard)', () => {
  const login = src('../pages/Login.jsx');
  assert.match(login, /\{guestAllowed && \(\n\s*<button type="button" onClick=\{continueAsGuest\}/);
  assert.match(login, /Continue as guest \(read-only\)/);
  assert.match(login, /\{FORGOT_PASSWORD_NOTE\}/);
  assert.match(login, /api\('\/auth\/guest', \{ method: 'POST', body: \{\} \}\)/);
  assert.equal((login.match(/Continue as guest \(read-only\)\n\s*<\/button>/g) || []).length, 1, 'one button');
  assert.match(login, /export default function Login\(\{ onSignedIn, guestAllowed = false \}\)/, 'off unless the app says so');
});

test('the app asks for setup only when the server says so, before any session check (wiring guard)', () => {
  const app = src('../App.jsx');
  const setupAt = app.indexOf('if (setupRequired(status))');
  const meAt = app.indexOf("await api('/auth/me')");
  assert.ok(setupAt > 0 && meAt > setupAt, 'the setup phase is decided before /auth/me is asked');
  assert.match(app, /guestAllowed: guests/);
  assert.match(app, /setAuth\(\(current\) => \(\{ \.\.\.current, phase: 'ready'/, 'signing in keeps what the status said, such as guestAllowed');
});

test('the setup form validates before sending, clears the passwords as it sends, and keeps nothing in the browser (wiring guard)', () => {
  const setup = src('../pages/Setup.jsx');
  assert.ok(setup.indexOf('validateFirstAdmin(form)') < setup.indexOf("api('/auth/setup', { method: 'POST', body })"));
  assert.ok(setup.indexOf('setForm({ ...EMPTY, username: form.username })') < setup.indexOf("api('/auth/setup', { method: 'POST', body })"));
  assert.doesNotMatch(setup, /localStorage|sessionStorage|console\./);
  assert.equal((setup.match(/type="password"/g) || []).length, 2);
  assert.match(setup, /Create the first administrator account/);
  assert.match(setup, /setCsrfToken\(session\.csrf_token\);\n\s*onSignedIn\(session\);/);
});

test('a password is reset only after validation and the confirmation panel, and is cleared as it is sent (wiring guard)', () => {
  const page = src('../components/UserManagement.jsx');
  assert.match(page, /onAskReset=\{askReset\}/, 'the first click only opens the panel');
  assert.match(page, /onConfirmReset=\{confirmReset\}/);
  const send = "await api(`/auth/users/${encodeURIComponent(username)}/password`, { method: 'POST', body })";
  assert.equal(page.split(send).length - 1, 1, 'one place sends a reset');
  assert.ok(page.indexOf('validatePasswordReset(resetForm)') < page.indexOf(send));
  assert.ok(page.indexOf('setResetForm(EMPTY_RESET);\n    setResetBusy(true)') < page.indexOf(send));
  assert.match(page, /resetBlockedReason\(user, me\)/);
  assert.match(page, /disabled=\{Boolean\(resetBlocked\) \|\| working \|\| Boolean\(confirming\)\}/);
  assert.doesNotMatch(page, /localStorage|sessionStorage|console\./);
});

test('Settings gives a guest no password form and no user table, and says what a guest is (wiring guard)', () => {
  const settings = src('../pages/Settings.jsx');
  assert.match(settings, /canChangePassword\(account\) && <ChangePasswordCard \/>/);
  assert.match(settings, /if \(account\.guest\) \{/);
  assert.match(settings, /A guest has no account and no password/);
});
