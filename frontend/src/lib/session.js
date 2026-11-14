// Pure helpers for signing in and out, and for the three authentication modes (no React, no DOM), so they can be unit-tested
// with `node --test`. The account session is an HttpOnly cookie that this code never reads; these helpers decide what the page
// shows and what each request carries.
//
// The mode comes from the backend's /auth/status and is 'unknown' until that answer arrives. Nothing protected is requested
// before then, and an unknown mode never sends a stored bearer token.

const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
const SIGN_IN_PATHS = ['/auth/login', '/auth/status'];

/** True for the methods that change data, which carry the CSRF header in accounts mode. */
export function isWriteMethod(method) {
  return WRITE_METHODS.includes(String(method || 'GET').toUpperCase());
}

/** The sign-in page is shown only when the server says sign-in is how people get in (accounts mode). */
export function signInRequired(status) {
  return Boolean(status && status.sign_in === true);
}

/** The Sign in button is enabled only when both fields have something in them. */
export function canSubmitSignIn({ username, password } = {}) {
  return String(username || '').trim().length > 0 && String(password || '').length > 0;
}

/** Human text for the role, as shown in the top bar and in Settings. */
export function roleLabel(role) {
  return { viewer: 'Viewer', analyst: 'Analyst', approver: 'Approver' }[role] || 'Unknown role';
}

/**
 * What the top bar says about who is using the page. It never shows a name that was not returned by the server, so nothing
 * looks signed in when it is not.
 */
export function identityLabel(user, mode) {
  if (user && user.authenticated && user.name) {
    return { title: user.name, subtitle: roleLabel(user.role) };
  }
  if (mode === 'disabled') return { title: 'Demo mode', subtitle: 'No sign-in: reviewer names are typed' };
  if (mode === 'token') return { title: 'Token access', subtitle: 'Bearer token from Settings' };
  return { title: 'Not signed in', subtitle: '' };
}

/** Sign-in failures in plain words. The server's own message is used where it is already safe to show. */
export function signInErrorMessage(err) {
  if (!err) return '';
  if (err.status === 0) return 'The server cannot be reached. Check that the backend is running.';
  if (err.status === 401) return 'Invalid username or password.';
  if (err.status === 429) return err.message || 'Too many failed sign-in attempts. Try again later.';
  return err.message || 'Sign-in failed. Try again.';
}

/**
 * The headers of one request, decided by the authentication mode.
 *  - accounts: never a bearer token, even one left in the browser. Writes carry the session's CSRF token.
 *  - token: the stored bearer token, as before. No CSRF header.
 *  - disabled, unknown: no authentication header at all.
 */
export function requestHeaders({ mode = 'unknown', storedToken = '', csrf = '', method = 'GET', hasBody = false } = {}) {
  const headers = {};
  if (hasBody) headers['Content-Type'] = 'application/json';
  if (mode === 'token' && String(storedToken || '').trim()) {
    headers.Authorization = `Bearer ${String(storedToken).trim()}`;
  }
  if (mode === 'accounts' && isWriteMethod(method) && csrf) {
    headers['X-CSRF-Token'] = csrf;
  }
  return headers;
}

/**
 * True when a 401 means the account session has ended and the page must go back to sign-in. Sign-in and the status check are
 * excluded, because a 401 there is an ordinary answer. Token and demo modes keep their own error messages.
 */
export function signedOutAfter({ mode, status, path }) {
  if (mode !== 'accounts' || status !== 401) return false;
  return !SIGN_IN_PATHS.some((p) => String(path || '').startsWith(p));
}

/**
 * What the Settings page shows for the Access area, by mode:
 *  - 'account': the signed-in account (accounts mode). The bearer-token card is not shown, because it does not apply.
 *  - 'token': the bearer-token card (token mode).
 *  - 'demo': the demo-mode card, which says no token is needed (disabled mode).
 *  - 'pending': the mode is not known yet, so nothing is claimed.
 */
export function settingsAccessView(mode) {
  if (mode === 'accounts') return 'account';
  if (mode === 'token') return 'token';
  if (mode === 'disabled') return 'demo';
  return 'pending';
}

/**
 * What a sign-out request means. Only a successful answer from the server is a confirmed revocation. A 401 means the session had
 * already ended on the server, so the page may clear its state. Anything else (no connection, a refused request) leaves the
 * session possibly open on the server, so the page must not claim it was revoked.
 */
export function signOutOutcome(err) {
  if (!err) return { revoked: true, endedElsewhere: false, message: '' };
  if (err.status === 401) return { revoked: false, endedElsewhere: true, message: '' };
  if (err.status === 0) {
    return { revoked: false, endedElsewhere: false, message: 'Could not reach the server, so your session may still be open there. Try signing out again.' };
  }
  if (err.status === 403) {
    return { revoked: false, endedElsewhere: false, message: 'The server refused the sign-out because the security token did not match. Reload the page, then sign out again.' };
  }
  return { revoked: false, endedElsewhere: false, message: 'Sign-out did not complete. Try again.' };
}
