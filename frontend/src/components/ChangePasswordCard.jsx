import React, { useState } from 'react';
import { ActionButton } from './StateCards';
import { api } from '../api';
import { MIN_PASSWORD_LENGTH, passwordChangeBody, passwordChangedMessage, validatePasswordChange } from '../lib/accountForms';

const input = { padding: '8px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px', width: '100%', maxWidth: '320px' };
const field = { display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '12px', color: 'var(--text-muted)' };
const problem = { fontSize: '12px', color: '#f87171' };

/** The "Change password" form, without any state of its own (so it can be rendered and tested from props). */
export function ChangePasswordForm({ form, errors = {}, busy = false, error = '', message = '', onChange, onSubmit }) {
  return (
    <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <label style={field}>
        Current password
        <input type="password" name="current_password" autoComplete="current-password" maxLength={1024} value={form.current}
          onChange={onChange('current')} style={input} disabled={busy} />
        {errors.current && <span role="alert" style={problem}>{errors.current}</span>}
      </label>
      <label style={field}>
        New password
        <input type="password" name="new_password" autoComplete="new-password" maxLength={1024} value={form.next}
          onChange={onChange('next')} style={input} disabled={busy} />
        {errors.next && <span role="alert" style={problem}>{errors.next}</span>}
      </label>
      <label style={field}>
        Confirm new password
        <input type="password" name="confirm_password" autoComplete="new-password" maxLength={1024} value={form.confirm}
          onChange={onChange('confirm')} style={input} disabled={busy} />
        {errors.confirm && <span role="alert" style={problem}>{errors.confirm}</span>}
      </label>
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        <ActionButton busy={busy} onClick={onSubmit}>Change password</ActionButton>
      </div>
      {error && <div role="alert" style={{ fontSize: '13px', color: '#f87171' }}>{error}</div>}
      {message && <div role="status" style={{ fontSize: '13px', color: '#10b981' }}>{message}</div>}
    </form>
  );
}

const EMPTY = { current: '', next: '', confirm: '' };

/**
 * Settings → Change password, for the signed-in account (accounts mode). The server checks the current password, ends the account's
 * other sessions and keeps this one open. Passwords are held only in this form, are cleared as soon as the request is sent, and are
 * never stored in the browser.
 */
export default function ChangePasswordCard() {
  const [form, setForm] = useState(EMPTY);
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const onChange = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }));

  const submit = async (event) => {
    if (event && event.preventDefault) event.preventDefault();
    if (busy) return;
    setMessage('');
    setError('');
    const check = validatePasswordChange(form);
    setErrors(check.errors);
    if (!check.valid) return;
    const body = passwordChangeBody(form);
    setForm(EMPTY);
    setBusy(true);
    try {
      setMessage(passwordChangedMessage(await api('/auth/password', { method: 'POST', body })));
    } catch (err) {
      setError(err.message || 'The password was not changed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="glass-card" style={{ marginBottom: '20px' }}>
      <h3 style={{ fontSize: '15px', marginBottom: '8px' }}>Change password</h3>
      <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
        Use at least {MIN_PASSWORD_LENGTH} characters. Your other sessions are signed out when the password changes; this one stays open.
        There is no reset by e-mail: if you forget your password, ask an approver to reset it.
      </p>
      <ChangePasswordForm form={form} errors={errors} busy={busy} error={error} message={message} onChange={onChange} onSubmit={submit} />
    </div>
  );
}
