// Pure helpers for signing in and out, and for the three authentication modes (no React, no DOM), so they can be unit-tested
// with `node --test`. The account session is an HttpOnly cookie that this code never reads; these helpers decide what the page
// shows and what each request carries.
//
// The mode comes from the backend's /auth/status and is 'unknown' until that answer arrives. Nothing protected is requested
// before then, and an unknown mode never sends a stored bearer token.

const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
// A 401 from these is an ordinary answer, not "the session ended": sign-in and the status check, and a password change whose current
// password was wrong (the session itself is fine).
const SIGN_IN_PATHS = ['/auth/login', '/auth/setup', '/auth/guest', '/auth/status', '/auth/password'];
// These do not use an existing session on the server (they start one or ask nothing of it), so a response from them does not
// restart the idle clock.
const NO_SESSION_ACTIVITY_PATHS = ['/auth/login', '/auth/setup', '/auth/guest', '/auth/status'];

/** Warn this long before the idle timeout ends the session, and this long before the absolute limit does. */
export const IDLE_WARNING_SECONDS = 120;
export const ABSOLUTE_WARNING_SECONDS = 300;

/** True for the methods that change data, which carry the CSRF header in accounts mode. */
export function isWriteMethod(method) {
  return WRITE_METHODS.includes(String(method || 'GET').toUpperCase());
}

/** The sign-in page is shown only when the server says sign-in is how people get in (accounts mode). */
export function signInRequired(status) {
  return Boolean(status && status.sign_in === true);
}

/** True when the server says no account exists yet, so the page offers "Create the first administrator account" instead of sign-in. */
export function setupRequired(status) {
  return signInRequired(status) && status.setup_required === true;
}

/** True when the sign-in page offers "Continue as guest (read-only)": accounts mode with ALLOW_GUEST, and an installation that has accounts. */
export function guestAllowed(status) {
  return signInRequired(status) && status.guest_allowed === true && status.setup_required !== true;
}

/** True for the read-only guest session (a viewer with no account), as reported by the server. */
export function isGuest(user) {
  return Boolean(user) && user.guest === true;
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
  if (user && user.authenticated && user.guest === true) return { title: 'Guest (read-only)', subtitle: '' };
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

/**
 * True when a response shows the account session is alive and was just used, so the idle clock restarts from now. The backend
 * records use on every authenticated request. Sign-in and the status check do not use an existing session, and a 401 or no
 * answer says nothing.
 */
export function countsAsActivity({ mode, status, path }) {
  if (mode !== 'accounts') return false;
  if (!Number.isFinite(status) || status === 0 || status === 401) return false;
  return !NO_SESSION_ACTIVITY_PATHS.some((p) => String(path || '').startsWith(p));
}

/**
 * When (milliseconds, on this page's clock) the session reaches its absolute limit, from the seconds the server reported in
 * `expires_in_seconds` and the moment the answer arrived. The server counts the seconds itself, so a wrong clock on this computer
 * does not matter. null when the server did not say.
 */
export function absoluteDeadline(session, receivedAt) {
  const left = Number(session && session.expires_in_seconds);
  if (session == null || session.expires_in_seconds == null || !Number.isFinite(left) || left < 0 || !Number.isFinite(receivedAt)) return null;
  return receivedAt + left * 1000;
}

/**
 * Whether the session is about to end, as of `now` (all times in milliseconds):
 *  - kind 'idle': the idle timeout ends it within IDLE_WARNING_SECONDS unless the user does something. "Stay signed in" helps.
 *  - kind 'absolute': the absolute limit ends it within ABSOLUTE_WARNING_SECONDS. Nothing extends it; the user signs in again.
 *  - kind 'expired': the time has passed, so the next request will be refused.
 *  - kind null: nothing to say yet (or the timing is not known).
 * When both limits are near, the one that comes first is reported. The idle clock starts at the last response that used the
 * session (`lastActivityAt`). The server notes use at most once a minute, so it may end a session up to a minute before this
 * estimate; the warning leaves at least that much time.
 */
export function sessionWarning({ now, lastActivityAt, idleTimeoutMinutes, absoluteDeadlineAt } = {}) {
  const none = { kind: null, secondsLeft: null };
  if (!Number.isFinite(now)) return none;
  const idleMinutes = Number(idleTimeoutMinutes);
  const idleLeft = idleMinutes > 0 && Number.isFinite(lastActivityAt) ? (lastActivityAt + idleMinutes * 60000 - now) / 1000 : Infinity;
  const absoluteLeft = Number.isFinite(absoluteDeadlineAt) ? (absoluteDeadlineAt - now) / 1000 : Infinity;
  if (Math.min(idleLeft, absoluteLeft) <= 0) return { kind: 'expired', secondsLeft: 0 };
  const idleNear = idleLeft <= IDLE_WARNING_SECONDS;
  const absoluteNear = absoluteLeft <= ABSOLUTE_WARNING_SECONDS;
  if (idleNear && (!absoluteNear || idleLeft < absoluteLeft)) return { kind: 'idle', secondsLeft: Math.ceil(idleLeft) };
  if (absoluteNear) return { kind: 'absolute', secondsLeft: Math.ceil(absoluteLeft) };
  return none;
}

/** "2 minutes", "1 minute", "45 seconds": a countdown in words, rounded up so it never says less time than is left. */
export function formatCountdown(seconds) {
  const total = Math.max(0, Math.ceil(Number(seconds) || 0));
  if (total >= 60) {
    const minutes = Math.ceil(total / 60);
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }
  return `${total} second${total === 1 ? '' : 's'}`;
}

/** The sentence for a warning from sessionWarning, or '' when there is none. */
export function sessionWarningMessage(warning) {
  if (!warning || !warning.kind) return '';
  if (warning.kind === 'expired') return 'Your session has ended.';
  if (warning.kind === 'idle') return `Your session will end in ${formatCountdown(warning.secondsLeft)} due to inactivity.`;
  return `Your session reaches its time limit in ${formatCountdown(warning.secondsLeft)}. Finish what you are doing; you will then need to sign in again.`;
}

/** "Stay signed in" is offered only for the idle warning: activity cannot extend the absolute limit. */
export function warningCanBeExtended(warning) {
  return Boolean(warning) && warning.kind === 'idle';
}
