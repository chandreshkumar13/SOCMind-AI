// Pure helpers for the account forms (first-run setup, create an account, change your password, reset someone's password, disable an account). No React and no DOM,
// so they can be unit-tested with `node --test`. The rules mirror the backend (app/services/accounts.py, passwords.py), which is the
// authority: a form that passes here can still be refused by the server, and its message is shown as it is.

export const ACCOUNT_ROLES = ['viewer', 'analyst', 'approver'];
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 1024;

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;

/** The note on the sign-in page: there is no e-mail reset, an approver sets a new password. */
export const FORGOT_PASSWORD_NOTE = 'Forgot your password? Ask an approver to reset it.';

export const USERNAME_RULE = 'A username is 3 to 64 characters: letters, digits, ".", "-" or "_", starting with a letter or digit.';

/** The stored form of a username (trimmed, lower case), or null when the text cannot be a username. */
export function normaliseUsername(raw) {
  if (typeof raw !== 'string') return null;
  const name = raw.trim().toLowerCase();
  return USERNAME_PATTERN.test(name) ? name : null;
}

/** Why a password cannot be used, in the backend's words, or '' when it can. Counts characters, not UTF-16 units, as the backend does. */
export function passwordProblem(password) {
  if (typeof password !== 'string' || password.length === 0) return 'Enter a password.';
  const length = Array.from(password).length;
  if (length < MIN_PASSWORD_LENGTH) return `The password must be at least ${MIN_PASSWORD_LENGTH} characters long.`;
  if (length > MAX_PASSWORD_LENGTH) return `The password must be at most ${MAX_PASSWORD_LENGTH} characters long.`;
  if (!password.trim()) return 'The password cannot be only spaces.';
  return '';
}

/** Checks the "Create account" form. Returns { valid, errors } with one message per field that needs attention. */
export function validateNewAccount({ username = '', role = '', password = '', confirm = '' } = {}) {
  const errors = {};
  if (normaliseUsername(username) === null) errors.username = USERNAME_RULE;
  if (!ACCOUNT_ROLES.includes(role)) errors.role = 'Choose a role.';
  const problem = passwordProblem(password);
  if (problem) errors.password = problem;
  if (password !== confirm) errors.confirm = 'The two passwords do not match.';
  return { valid: Object.keys(errors).length === 0, errors };
}

/** Checks the "Change password" form. Returns { valid, errors } with one message per field that needs attention. */
export function validatePasswordChange({ current = '', next = '', confirm = '' } = {}) {
  const errors = {};
  if (!current) errors.current = 'Enter your current password.';
  const problem = passwordProblem(next);
  if (problem) errors.next = problem;
  else if (current && next === current) errors.next = 'The new password must be different from the current one.';
  if (next !== confirm) errors.confirm = 'The two passwords do not match.';
  return { valid: Object.keys(errors).length === 0, errors };
}

/** Checks the first-run setup form: a username and a password typed twice. The role is not chosen; the first account is an approver. */
export function validateFirstAdmin({ username = '', password = '', confirm = '' } = {}) {
  const errors = {};
  if (normaliseUsername(username) === null) errors.username = USERNAME_RULE;
  const problem = passwordProblem(password);
  if (problem) errors.password = problem;
  if (password !== confirm) errors.confirm = 'The two passwords do not match.';
  return { valid: Object.keys(errors).length === 0, errors };
}

/** The request body for POST /auth/setup. The password is sent exactly as typed, with its confirmation. */
export function setupBody({ username, password, confirm }) {
  return { username: normaliseUsername(username) || String(username || '').trim(), password, confirm };
}

/** Checks the approver's "Reset password" form for another account: a new password typed twice. */
export function validatePasswordReset({ next = '', confirm = '' } = {}) {
  const errors = {};
  const problem = passwordProblem(next);
  if (problem) errors.next = problem;
  if (next !== confirm) errors.confirm = 'The two passwords do not match.';
  return { valid: Object.keys(errors).length === 0, errors };
}

/** The request body for POST /auth/users/{username}/password. The password is sent exactly as typed. */
export function passwordResetBody({ next }) {
  return { new_password: next };
}

/**
 * Why Reset password is not offered for an account, or '' when it is. The server refuses your own account too (409): an approver
 * changes their own password with Change password, which asks for the current one.
 */
export function resetBlockedReason(target, me) {
  if (target && me && me.name && target.username === me.name) return 'Use Change password for your own account.';
  return '';
}

/** The sentence shown before a password is reset. */
export function resetConfirmation(username) {
  return `Set a new password for ${username}? Every open session of ${username} ends at once, and the old password stops working.`;
}

/** What a successful reset tells the approver. The password is never part of it. */
export function passwordResetMessage(username, result) {
  const ended = Number(result && result.sessions_ended) || 0;
  const sessions = ended === 0 ? 'They had no open sessions.' : `${ended} open session${ended === 1 ? '' : 's'} ended.`;
  return `Password reset for "${username}". ${sessions} Give them the new password in person; it is not shown again.`;
}

/** Changing your own password needs a real account: the read-only guest has none. */
export function canChangePassword(account) {
  return Boolean(account) && account.authenticated === true && account.guest !== true;
}

/** The request body for POST /auth/users. The username is sent in its stored form; the password is sent exactly as typed. */
export function createAccountBody({ username, role, password }) {
  return { username: normaliseUsername(username) || String(username || '').trim(), role, password };
}

/** The request body for POST /auth/password. Both passwords are sent exactly as typed. */
export function passwordChangeBody({ current, next }) {
  return { current_password: current, new_password: next };
}

/** Account management is shown only to a signed-in approver in accounts mode. The backend enforces it; this only hides the controls. */
export function canManageUsers(account, mode) {
  return mode === 'accounts' && Boolean(account) && account.authenticated === true && account.guest !== true && account.role === 'approver';
}

/**
 * Why an account's Disable button is not offered, or '' when it is. The backend enforces both rules (409); this keeps the button
 * honest: nobody disables their own account, and the last active approver stays active.
 */
export function disableBlockedReason(users, target, me) {
  if (!target || !target.is_active) return '';
  if (me && me.name && target.username === me.name) return 'You cannot disable your own account.';
  if (target.role === 'approver') {
    const otherApprovers = (users || []).filter((u) => u.is_active && u.role === 'approver' && u.username !== target.username).length;
    if (otherApprovers === 0) return 'The last active approver cannot be disabled.';
  }
  return '';
}

/** The sentence shown before an account is disabled. */
export function disableConfirmation(username) {
  return `Disable ${username}? Their open sessions end immediately, and they cannot sign in until an approver enables the account again.`;
}

/** What a successful password change tells the user. */
export function passwordChangedMessage(result) {
  const ended = Number(result && result.other_sessions_ended) || 0;
  if (ended === 0) return 'Password changed. You have no other open sessions.';
  return `Password changed. ${ended} other session${ended === 1 ? ' was' : 's were'} signed out.`;
}
