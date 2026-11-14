import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  canSubmitSignIn, identityLabel, isWriteMethod, requestHeaders, roleLabel, settingsAccessView, signInErrorMessage,
  signInRequired, signOutOutcome, signedOutAfter,
} from './session.js';

// Reads a source file for the wiring checks. Line endings are normalised so the patterns below match on every platform.
const src = (path) => readFileSync(new URL(path, import.meta.url), 'utf8').replace(/\r\n/g, '\n');

// ----------------------------------------------------------------------------------- write methods and sign-in helpers
test('only the methods that change data are write methods', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'post', 'delete']) assert.equal(isWriteMethod(method), true, method);
  for (const method of ['GET', 'HEAD', 'OPTIONS', undefined, '']) assert.equal(isWriteMethod(method), false, String(method));
});

test('the sign-in page is shown only when the server says sign-in is how people get in', () => {
  assert.equal(signInRequired({ mode: 'accounts', sign_in: true }), true);
  assert.equal(signInRequired({ mode: 'token', sign_in: false }), false);
  assert.equal(signInRequired({ mode: 'disabled', sign_in: false }), false);
  assert.equal(signInRequired(null), false);
  assert.equal(signInRequired(undefined), false);
});

test('the sign-in button needs a username and a password', () => {
  assert.equal(canSubmitSignIn({ username: 'ana', password: 'x' }), true);
  assert.equal(canSubmitSignIn({ username: '   ', password: 'x' }), false);
  assert.equal(canSubmitSignIn({ username: 'ana', password: '' }), false);
  assert.equal(canSubmitSignIn({}), false);
  assert.equal(canSubmitSignIn(undefined), false);
});

test('roles have plain labels, and an unknown role is never shown as a known one', () => {
  assert.equal(roleLabel('viewer'), 'Viewer');
  assert.equal(roleLabel('analyst'), 'Analyst');
  assert.equal(roleLabel('approver'), 'Approver');
  assert.equal(roleLabel('root'), 'Unknown role');
});

test('the top bar names the account only when the server returned one, and otherwise says who is not signed in', () => {
  assert.deepEqual(identityLabel({ authenticated: true, name: 'ana.analyst', role: 'analyst' }, 'accounts'),
    { title: 'ana.analyst', subtitle: 'Analyst' });
  assert.deepEqual(identityLabel(null, 'accounts'), { title: 'Not signed in', subtitle: '' });
  assert.deepEqual(identityLabel({ authenticated: false, name: 'ghost', role: 'approver' }, 'accounts'),
    { title: 'Not signed in', subtitle: '' }, 'an unauthenticated record must never show a name');
  assert.equal(identityLabel(null, 'disabled').title, 'Demo mode');
  assert.equal(identityLabel(null, 'token').title, 'Token access');
});

test('sign-in failures are explained without guessing: wrong credentials, lockout, unreachable server', () => {
  assert.equal(signInErrorMessage({ status: 401, message: 'Invalid username or password.' }), 'Invalid username or password.');
  assert.match(signInErrorMessage({ status: 429, message: 'Too many failed sign-in attempts from this address. Try again in 15 minutes.' }), /Too many/);
  assert.match(signInErrorMessage({ status: 0, message: 'Cannot reach the backend' }), /cannot be reached/);
  assert.equal(signInErrorMessage(null), '');
  assert.equal(signInErrorMessage({ status: 500, message: 'Sign-in failed. Try again.' }), 'Sign-in failed. Try again.');
});

// ----------------------------------------------------------------------------------- request headers by mode
test('accounts mode never sends a stored bearer token, even one left in the browser', () => {
  const headers = requestHeaders({ mode: 'accounts', storedToken: 'old-bearer-token-0123456789', method: 'GET' });
  assert.equal(headers.Authorization, undefined);
  const write = requestHeaders({ mode: 'accounts', storedToken: 'old-bearer-token-0123456789', csrf: 'csrf-value', method: 'POST', hasBody: true });
  assert.equal(write.Authorization, undefined, 'a write must not fall back to the stored bearer token');
});

test('accounts mode sends the CSRF header on writes only, and only when a session token is held', () => {
  assert.deepEqual(requestHeaders({ mode: 'accounts', csrf: 'abc', method: 'POST' }), { 'X-CSRF-Token': 'abc' });
  assert.deepEqual(requestHeaders({ mode: 'accounts', csrf: 'abc', method: 'DELETE' }), { 'X-CSRF-Token': 'abc' });
  assert.deepEqual(requestHeaders({ mode: 'accounts', csrf: 'abc', method: 'GET' }), {});
  assert.deepEqual(requestHeaders({ mode: 'accounts', csrf: '', method: 'POST' }), {}, 'no session token means no header is invented');
});

test('token mode sends the stored bearer token and no CSRF header, as before', () => {
  assert.deepEqual(requestHeaders({ mode: 'token', storedToken: '  tok-123  ', method: 'GET' }), { Authorization: 'Bearer tok-123' });
  assert.deepEqual(requestHeaders({ mode: 'token', storedToken: '', method: 'GET' }), {});
  assert.equal(requestHeaders({ mode: 'token', storedToken: 'tok-123', csrf: 'abc', method: 'POST' })['X-CSRF-Token'], undefined);
});

test('demo mode and an unknown mode send no authentication header, even if a token is stored', () => {
  assert.deepEqual(requestHeaders({ mode: 'disabled', storedToken: 'tok-123' }), {});
  assert.deepEqual(requestHeaders({ mode: 'unknown', storedToken: 'tok-123' }), {}, 'nothing is sent before the mode is known');
  assert.deepEqual(requestHeaders({}), {});
});

test('a JSON body adds its content type in every mode', () => {
  assert.equal(requestHeaders({ mode: 'accounts', hasBody: true })['Content-Type'], 'application/json');
  assert.equal(requestHeaders({ mode: 'disabled', hasBody: false })['Content-Type'], undefined);
});

// ----------------------------------------------------------------------------------- when a 401 sends the user back to sign-in
test('in accounts mode a 401 on a protected request means the session ended, so sign-in must return', () => {
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/alerts' }), true);
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/auth/logout' }), true);
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/auth/me' }), true);
});

test('sign-in and the status check never trigger the return, and other statuses do not either', () => {
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/auth/login' }), false);
  assert.equal(signedOutAfter({ mode: 'accounts', status: 401, path: '/auth/status' }), false);
  assert.equal(signedOutAfter({ mode: 'accounts', status: 403, path: '/alerts/seed' }), false, 'a refused write is not a session end');
  assert.equal(signedOutAfter({ mode: 'accounts', status: 500, path: '/alerts' }), false);
});

test('token and demo modes keep their own error messages on a 401', () => {
  assert.equal(signedOutAfter({ mode: 'token', status: 401, path: '/alerts' }), false);
  assert.equal(signedOutAfter({ mode: 'disabled', status: 401, path: '/alerts' }), false);
  assert.equal(signedOutAfter({ mode: 'unknown', status: 401, path: '/alerts' }), false);
});

// ----------------------------------------------------------------------------------- Settings by mode
test('Settings shows the account card in accounts mode, the token card in token mode, the demo card in demo mode', () => {
  assert.equal(settingsAccessView('accounts'), 'account');
  assert.equal(settingsAccessView('token'), 'token');
  assert.equal(settingsAccessView('disabled'), 'demo');
});

test('Settings claims nothing about access until the mode is known', () => {
  assert.equal(settingsAccessView('unknown'), 'pending');
  assert.equal(settingsAccessView(null), 'pending');
  assert.equal(settingsAccessView(undefined), 'pending');
});

// ----------------------------------------------------------------------------------- sign-out outcomes
test('a successful sign-out is the only answer that reports a server-side revocation', () => {
  assert.deepEqual(signOutOutcome(null), { revoked: true, endedElsewhere: false, message: '' });
});

test('a 401 on sign-out means the session already ended on the server, so the page may clear its state', () => {
  const outcome = signOutOutcome({ status: 401, message: 'Sign in to continue.' });
  assert.equal(outcome.revoked, false);
  assert.equal(outcome.endedElsewhere, true);
});

test('a network failure or a refused sign-out is never reported as revoked, and explains what to do', () => {
  const offline = signOutOutcome({ status: 0, message: 'Cannot reach the backend' });
  assert.equal(offline.revoked, false);
  assert.equal(offline.endedElsewhere, false);
  assert.match(offline.message, /may still be open/);
  const refused = signOutOutcome({ status: 403, message: 'A valid CSRF token is required for this request.' });
  assert.equal(refused.revoked, false);
  assert.equal(refused.endedElsewhere, false);
  assert.match(refused.message, /Reload the page/);
  const other = signOutOutcome({ status: 500, message: 'boom' });
  assert.equal(other.revoked, false);
  assert.match(other.message, /did not complete/);
});

// ----------------------------------------------------------------------------------- wiring guards
test('the API client takes its headers from the mode rules, never from the stored token directly (wiring guard)', () => {
  const api = src('../api.js');
  assert.match(api, /const headers = requestHeaders\(\{\n\s*mode: authMode,\n\s*storedToken: readStoredToken\(\),\n\s*csrf: csrfToken,/);
  assert.doesNotMatch(api, /authHeaders\(readStoredToken\(\)\)/, 'the stored bearer token must not be attached to every request');
  assert.match(api, /credentials: 'include'/);
  assert.doesNotMatch(api, /localStorage/, 'the session must never be written to localStorage');
});

test('a 401 from a protected request returns the page to sign-in only in accounts mode (wiring guard)', () => {
  const api = src('../api.js');
  assert.match(api, /if \(signedOutAfter\(\{ mode: authMode, status: res\.status, path \}\)\) \{/);
});

test('the app sets the mode before protected data, and clears a stored bearer token in accounts mode (wiring guard)', () => {
  const app = src('../App.jsx');
  const modeAt = app.indexOf('setAuthMode(status.mode);');
  const clearAt = app.indexOf("if (status.mode === 'accounts') storeToken('');");
  const gateAt = app.indexOf("if (auth.phase === 'ready') refreshAll();");
  assert.ok(modeAt > 0 && clearAt > modeAt, 'the mode is set, then a stale token is cleared in accounts mode');
  assert.ok(gateAt > modeAt, 'data is requested only after the mode is known');
});

test('the app loads nothing until sign-in is confirmed, and clears the data when a session ends (wiring guard)', () => {
  const app = src('../App.jsx');
  assert.match(app, /if \(auth\.phase === 'ready'\) refreshAll\(\);/);
  assert.doesNotMatch(app, /useEffect\(\(\) => \{\n\s*refreshAll\(\);\n\s*\}, \[refreshAll\]\)/, 'refreshAll must not run on mount unconditionally');
  assert.match(app, /if \(auth\.phase === 'signin'\) return <Login onSignedIn=\{handleSignedIn\} \/>;/);
  assert.match(app, /window\.addEventListener\(SIGNED_OUT_EVENT, onSignedOut\)/);
  assert.match(app, /await api\('\/auth\/logout', \{ method: 'POST' \}\)/);
});

test('sign-out keeps the user signed in and shows the error unless the server confirmed it or the session had already ended (wiring guard)', () => {
  const app = src('../App.jsx');
  assert.match(app, /const outcome = signOutOutcome\(err\);/);
  assert.match(app, /if \(!outcome\.revoked && !outcome\.endedElsewhere\) \{\n\s*setSignOutError\(outcome\.message\);\n\s*return;/);
  assert.match(app, /<ErrorCard title="Sign-out did not complete"/);
  assert.doesNotMatch(app, /already ended, or the server is unreachable/, 'no error may be silently ignored any more');
});

test('Settings hides the bearer-token card in accounts mode and shows the account instead (wiring guard)', () => {
  const settings = src('../pages/Settings.jsx');
  assert.match(settings, /settingsAccessView\(authMode\) === 'account' && <AccountCard account=\{account\} \/>/);
  assert.match(settings, /\(settingsAccessView\(authMode\) === 'token' \|\| settingsAccessView\(authMode\) === 'demo'\) && <AccessCard \/>/);
  assert.doesNotMatch(settings, /\n\s*<AccessCard \/>\n/, 'the card must not be shown unconditionally');
});

test('the sign-in form keeps the password out of storage and off the URL, and marks it for password managers (wiring guard)', () => {
  const login = src('../pages/Login.jsx');
  assert.match(login, /autoComplete="current-password"/);
  assert.match(login, /type="password"/);
  assert.match(login, /setPassword\(''\);/, 'the password is cleared from the page once the request starts');
  assert.match(login, /api\('\/auth\/login', \{ method: 'POST', body: attempt \}\)/);
  assert.doesNotMatch(login, /localStorage|sessionStorage|location\.(href|search)/);
});

test('the top bar no longer shows a hard-coded person (wiring guard)', () => {
  const topbar = src('../components/Topbar.jsx');
  assert.doesNotMatch(topbar, /Chandresh|Lead SOC Analyst/);
  assert.match(topbar, /identityLabel\(user, mode\)/);
  assert.match(topbar, /onSignOut && user &&/, 'the sign-out control appears only for a real session');
});
