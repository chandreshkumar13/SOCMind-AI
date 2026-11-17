import React, { useState } from 'react';
import { ActionButton, ErrorCard, LoadingCard } from './StateCards';
import { api } from '../api';
import useAsync from '../lib/useAsync';
import { formatUtc } from '../lib/view';
import { roleLabel } from '../lib/session';
import {
  ACCOUNT_ROLES, MIN_PASSWORD_LENGTH, createAccountBody, disableBlockedReason, disableConfirmation, passwordResetBody,
  passwordResetMessage, resetBlockedReason, resetConfirmation, validateNewAccount, validatePasswordReset,
} from '../lib/accountForms';

const input = { padding: '8px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px', width: '100%', maxWidth: '320px' };
const field = { display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '12px', color: 'var(--text-muted)' };
const problem = { fontSize: '12px', color: '#f87171' };

/** The "Create account" form, without any state of its own (so it can be rendered and tested from props). */
export function CreateAccountForm({ form, errors = {}, busy = false, error = '', message = '', onChange, onSubmit }) {
  return (
    <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }} aria-label="Create account">
      <label style={field}>
        Username
        <input name="new_username" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={64} value={form.username}
          onChange={onChange('username')} style={input} disabled={busy} />
        {errors.username && <span role="alert" style={problem}>{errors.username}</span>}
      </label>
      <label style={field}>
        Role
        <select name="new_role" aria-label="Role for the new account" value={form.role} onChange={onChange('role')} style={input} disabled={busy}>
          {ACCOUNT_ROLES.map((role) => <option key={role} value={role}>{roleLabel(role)}</option>)}
        </select>
        {errors.role && <span role="alert" style={problem}>{errors.role}</span>}
      </label>
      <label style={field}>
        Password
        <input type="password" name="new_account_password" autoComplete="new-password" maxLength={1024} value={form.password}
          onChange={onChange('password')} style={input} disabled={busy} />
        {errors.password && <span role="alert" style={problem}>{errors.password}</span>}
      </label>
      <label style={field}>
        Confirm password
        <input type="password" name="new_account_confirm" autoComplete="new-password" maxLength={1024} value={form.confirm}
          onChange={onChange('confirm')} style={input} disabled={busy} />
        {errors.confirm && <span role="alert" style={problem}>{errors.confirm}</span>}
      </label>
      <div><ActionButton busy={busy} onClick={onSubmit}>Create account</ActionButton></div>
      {error && <div role="alert" style={{ fontSize: '13px', color: '#f87171' }}>{error}</div>}
      {message && <div role="status" style={{ fontSize: '13px', color: '#10b981' }}>{message}</div>}
    </form>
  );
}

/**
 * The "Reset password" panel of one row: the confirmation sentence, a new password typed twice, and Confirm / Cancel. Stateless, so it
 * can be rendered and tested from props. Nothing is sent until Confirm reset is pressed.
 */
export function ResetPasswordPanel({ username, form, errors = {}, busy = false, error = '', onChange, onConfirm, onCancel }) {
  return (
    <form role="alertdialog" aria-label={`Reset the password of ${username}`} onSubmit={onConfirm} style={{ maxWidth: '360px', display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{resetConfirmation(username)}</div>
      <label style={field}>
        New password
        <input type="password" name={`reset_password_${username}`} autoComplete="new-password" maxLength={1024} value={form.next}
          onChange={onChange('next')} style={input} disabled={busy} />
        {errors.next && <span role="alert" style={problem}>{errors.next}</span>}
      </label>
      <label style={field}>
        Confirm new password
        <input type="password" name={`reset_confirm_${username}`} autoComplete="new-password" maxLength={1024} value={form.confirm}
          onChange={onChange('confirm')} style={input} disabled={busy} />
        {errors.confirm && <span role="alert" style={problem}>{errors.confirm}</span>}
      </label>
      <div style={{ display: 'flex', gap: '8px' }}>
        <ActionButton variant="danger" busy={busy} onClick={onConfirm}>Confirm reset</ActionButton>
        <ActionButton variant="ghost" disabled={busy} onClick={onCancel}>Cancel</ActionButton>
      </div>
      {error && <div role="alert" style={{ fontSize: '12px', color: '#f87171' }}>{error}</div>}
    </form>
  );
}

/**
 * The accounts table. Each row offers Disable (after a confirmation) or Enable, and Reset password (a form with a confirmation). Disable is not offered for your own account or for
 * the last active approver; the server refuses both as well. No password or hash is ever part of a row.
 */
export function UsersTable({
  users, me, confirming = null, busyName = null, error = '', onAskDisable, onCancel, onConfirmDisable, onEnable,
  resetting = null, resetForm = { next: '', confirm: '' }, resetErrors = {}, resetBusy = false, resetError = '', resetMessage = '',
  onAskReset, onResetChange, onConfirmReset, onCancelReset,
}) {
  return (
    <div>
      <div className="table-container">
        <table className="cyber-table">
          <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Created (UTC)</th><th>Action</th></tr></thead>
          <tbody>
            {users.map((user) => {
              const blocked = disableBlockedReason(users, user, me);
              const resetBlocked = resetBlockedReason(user, me);
              const working = busyName === user.username;
              return (
                <tr key={user.username}>
                  <td className="code-font" style={{ fontWeight: 600 }}>{user.username}{me && me.name === user.username ? ' (you)' : ''}</td>
                  <td>{roleLabel(user.role)}</td>
                  <td style={{ color: user.is_active ? '#10b981' : '#f87171' }}>{user.is_active ? 'Active' : 'Disabled'}</td>
                  <td className="code-font" style={{ fontSize: '12px', whiteSpace: 'nowrap' }}>{formatUtc(user.created_at)}</td>
                  <td>
                    {!user.is_active && <ActionButton variant="ghost" busy={working} onClick={() => onEnable(user.username)}>Enable</ActionButton>}
                    {user.is_active && confirming !== user.username && (
                      <ActionButton variant="danger" disabled={Boolean(blocked) || working} title={blocked || undefined} onClick={() => onAskDisable(user.username)}>Disable</ActionButton>
                    )}
                    {resetting !== user.username && (
                      <span style={{ marginLeft: '8px' }}>
                        <ActionButton variant="ghost" disabled={Boolean(resetBlocked) || working || Boolean(confirming)} title={resetBlocked || undefined}
                          onClick={() => onAskReset(user.username)}>Reset password</ActionButton>
                      </span>
                    )}
                    {resetting === user.username && (
                      <ResetPasswordPanel username={user.username} form={resetForm} errors={resetErrors} busy={resetBusy} error={resetError}
                        onChange={onResetChange} onConfirm={onConfirmReset} onCancel={onCancelReset} />
                    )}
                    {user.is_active && confirming === user.username && (
                      <div role="alertdialog" aria-label={`Confirm disabling ${user.username}`} style={{ maxWidth: '360px' }}>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>{disableConfirmation(user.username)}</div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <ActionButton variant="danger" busy={working} onClick={() => onConfirmDisable(user.username)}>Confirm disable</ActionButton>
                          <ActionButton variant="ghost" disabled={working} onClick={onCancel}>Cancel</ActionButton>
                        </div>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {error && <div role="alert" style={{ fontSize: '13px', color: '#f87171', marginTop: '8px' }}>{error}</div>}
      {resetMessage && <div role="status" style={{ fontSize: '13px', color: '#10b981', marginTop: '8px' }}>{resetMessage}</div>}
    </div>
  );
}

const EMPTY_RESET = { next: '', confirm: '' };
const EMPTY_FORM = { username: '', role: 'viewer', password: '', confirm: '' };

/**
 * Settings → Users, shown only to a signed-in approver in accounts mode (the server enforces it too). An approver lists the accounts,
 * creates one (username, role, password typed twice), disables or enables an account, and resets someone's password (a forgotten
 * password; there is no e-mail reset). There is no public sign-up. Passwords are held only in the forms, are cleared as soon as the
 * request is sent, and are never stored in the browser.
 */
export default function UserManagement({ account }) {
  const { loading, error: loadError, data: users, reload } = useAsync(() => api('/auth/users'), []);
  const [form, setForm] = useState(EMPTY_FORM);
  const [errors, setErrors] = useState({});
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');
  const [created, setCreated] = useState('');
  const [confirming, setConfirming] = useState(null);
  const [busyName, setBusyName] = useState(null);
  const [rowError, setRowError] = useState('');
  const [resetting, setResetting] = useState(null);
  const [resetForm, setResetForm] = useState(EMPTY_RESET);
  const [resetErrors, setResetErrors] = useState({});
  const [resetBusy, setResetBusy] = useState(false);
  const [resetError, setResetError] = useState('');
  const [resetMessage, setResetMessage] = useState('');

  const onChange = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }));

  const create = async (event) => {
    if (event && event.preventDefault) event.preventDefault();
    if (creating) return;
    setCreated('');
    setCreateError('');
    const check = validateNewAccount(form);
    setErrors(check.errors);
    if (!check.valid) return;
    const body = createAccountBody(form);
    setForm({ ...EMPTY_FORM, role: form.role });
    setCreating(true);
    try {
      const made = await api('/auth/users', { method: 'POST', body });
      setCreated(`Created the ${made.role} account "${made.username}". Give them their password in person; it is not shown again.`);
      await reload();
    } catch (err) {
      setCreateError(err.message || 'The account was not created.');
    } finally {
      setCreating(false);
    }
  };

  const change = async (username, action) => {
    setBusyName(username);
    setRowError('');
    try {
      await api(`/auth/users/${encodeURIComponent(username)}/${action}`, { method: 'POST' });
      setConfirming(null);
      await reload();
    } catch (err) {
      setRowError(err.message || `Could not ${action} the account.`);
    } finally {
      setBusyName(null);
    }
  };

  const askReset = (username) => {
    setRowError('');
    setResetMessage('');
    setResetError('');
    setResetErrors({});
    setResetForm(EMPTY_RESET);
    setConfirming(null);
    setResetting(username);
  };
  const cancelReset = () => { setResetting(null); setResetForm(EMPTY_RESET); setResetErrors({}); setResetError(''); };
  const onResetChange = (key) => (event) => setResetForm((current) => ({ ...current, [key]: event.target.value }));

  const confirmReset = async (event) => {
    if (event && event.preventDefault) event.preventDefault();
    if (resetBusy || !resetting) return;
    setResetError('');
    const check = validatePasswordReset(resetForm);
    setResetErrors(check.errors);
    if (!check.valid) return;
    const username = resetting;
    const body = passwordResetBody(resetForm);
    setResetForm(EMPTY_RESET);
    setResetBusy(true);
    try {
      const result = await api(`/auth/users/${encodeURIComponent(username)}/password`, { method: 'POST', body });
      setResetting(null);
      setResetMessage(passwordResetMessage(username, result));
    } catch (err) {
      setResetError(err.message || 'The password was not reset.');
    } finally {
      setResetBusy(false);
    }
  };

  return (
    <div className="glass-card" style={{ marginBottom: '20px' }}>
      <h3 style={{ fontSize: '15px', marginBottom: '8px' }}>Users</h3>
      <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
        Only an approver sees this. Accounts are created here by an approver; there is no public sign-up. Disabling an account ends its
        sessions at once. If someone forgets their password, reset it here (there is no e-mail reset): their sessions end and you give them
        the new password in person. Passwords need at least {MIN_PASSWORD_LENGTH} characters.
      </p>
      {loading && !users && <LoadingCard>Loading accounts...</LoadingCard>}
      {loadError && <ErrorCard title="Could not load the accounts" message={loadError} onRetry={reload} />}
      {users && (
        <UsersTable users={users} me={account} confirming={confirming} busyName={busyName} error={rowError}
          onAskDisable={(name) => { setRowError(''); setConfirming(name); }} onCancel={() => setConfirming(null)}
          onConfirmDisable={(name) => change(name, 'disable')} onEnable={(name) => change(name, 'enable')}
          resetting={resetting} resetForm={resetForm} resetErrors={resetErrors} resetBusy={resetBusy} resetError={resetError}
          resetMessage={resetMessage} onAskReset={askReset} onResetChange={onResetChange} onConfirmReset={confirmReset} onCancelReset={cancelReset} />
      )}
      <h4 style={{ fontSize: '13px', margin: '18px 0 10px' }}>Create account</h4>
      <CreateAccountForm form={form} errors={errors} busy={creating} error={createError} message={created} onChange={onChange} onSubmit={create} />
    </div>
  );
}
