import React, { useState } from 'react';
import { UserPlus } from 'lucide-react';
import { api, setCsrfToken } from '../api';
import { MIN_PASSWORD_LENGTH, setupBody, validateFirstAdmin } from '../lib/accountForms';

const input = { padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '14px', width: '100%' };
const label = { display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' };
const problem = { fontSize: '12px', color: '#f87171' };

/** The first-run form, without any state of its own (so it can be rendered and tested from props). */
export function SetupForm({ form, errors = {}, busy = false, error = '', onChange, onSubmit }) {
  return (
    <form className="glass-card" onSubmit={onSubmit} aria-labelledby="setup-title"
      style={{ width: '100%', maxWidth: '420px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div>
        <h1 id="setup-title" style={{ fontSize: '20px', color: '#ffffff', marginBottom: '6px' }}>Create the first administrator account</h1>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          No account exists yet. This one becomes an approver, who can create the other accounts. This page appears only until the first
          account exists, so create it before anyone else can reach this address. Use at least {MIN_PASSWORD_LENGTH} characters for the password.
        </p>
      </div>
      <label style={label}>
        Username
        <input name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} maxLength={64}
          value={form.username} onChange={onChange('username')} style={input} disabled={busy} />
        {errors.username && <span role="alert" style={problem}>{errors.username}</span>}
      </label>
      <label style={label}>
        Password
        <input type="password" name="new_password" autoComplete="new-password" maxLength={1024}
          value={form.password} onChange={onChange('password')} style={input} disabled={busy} />
        {errors.password && <span role="alert" style={problem}>{errors.password}</span>}
      </label>
      <label style={label}>
        Confirm password
        <input type="password" name="confirm_password" autoComplete="new-password" maxLength={1024}
          value={form.confirm} onChange={onChange('confirm')} style={input} disabled={busy} />
        {errors.confirm && <span role="alert" style={problem}>{errors.confirm}</span>}
      </label>
      {error && <div role="alert" style={{ fontSize: '13px', color: '#f87171' }}>{error}</div>}
      <button type="submit" disabled={busy}
        style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '10px 14px',
          borderRadius: 'var(--radius-sm)', border: 'none', fontWeight: 700, fontSize: '14px',
          background: 'linear-gradient(135deg, #00f2fe, #4facfe)', color: '#090d16',
          cursor: busy ? 'not-allowed' : 'pointer', opacity: busy ? 0.5 : 1,
        }}>
        <UserPlus size={14} /> {busy ? 'Creating...' : 'Create account and sign in'}
      </button>
    </form>
  );
}

const EMPTY = { username: '', password: '', confirm: '' };

/**
 * First-run setup, shown instead of the sign-in page while the server reports that no account exists. It creates one approver and
 * signs that person in. The passwords are cleared from the page as soon as the request starts and are never stored in the browser.
 */
export default function Setup({ onSignedIn }) {
  const [form, setForm] = useState(EMPTY);
  const [errors, setErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const onChange = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }));

  const submit = async (event) => {
    if (event && event.preventDefault) event.preventDefault();
    if (busy) return;
    setError('');
    const check = validateFirstAdmin(form);
    setErrors(check.errors);
    if (!check.valid) return;
    const body = setupBody(form);
    setForm({ ...EMPTY, username: form.username });
    setBusy(true);
    try {
      const session = await api('/auth/setup', { method: 'POST', body });
      setCsrfToken(session.csrf_token);
      onSignedIn(session);
    } catch (err) {
      setError(err.status === 409
        ? 'An account already exists, so setup is closed. Reload the page and sign in.'
        : (err.message || 'The account was not created.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
      <SetupForm form={form} errors={errors} busy={busy} error={error} onChange={onChange} onSubmit={submit} />
    </div>
  );
}
