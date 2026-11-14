import React, { useState } from 'react';
import { LogIn } from 'lucide-react';
import { api, setCsrfToken } from '../api';
import { canSubmitSignIn, signInErrorMessage } from '../lib/session';

const input = { padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '14px', width: '100%' };
const label = { display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' };

/**
 * The sign-in page. It is the only thing shown until the server confirms a session, so nothing about the data is loaded before
 * sign-in. The password is cleared from the page as soon as the request starts; nothing is stored in the browser.
 */
export default function Login({ onSignedIn }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const ready = canSubmitSignIn({ username, password }) && !busy;

  const submit = async (event) => {
    event.preventDefault();
    if (!ready) return;
    const attempt = { username: username.trim(), password };
    setPassword('');
    setBusy(true);
    setError('');
    try {
      const session = await api('/auth/login', { method: 'POST', body: attempt });
      setCsrfToken(session.csrf_token);
      onSignedIn(session);
    } catch (err) {
      setError(signInErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
      <form className="glass-card" onSubmit={submit} aria-labelledby="signin-title"
        style={{ width: '100%', maxWidth: '380px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 id="signin-title" style={{ fontSize: '20px', color: '#ffffff', marginBottom: '6px' }}>Sign in to SOCMind AI</h1>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Use the account your administrator created. A session ends after 30 minutes without use, and after 8 hours at most.
          </p>
        </div>
        <label style={label}>
          Username
          <input name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} maxLength={64}
            value={username} onChange={(e) => setUsername(e.target.value)} style={input} disabled={busy} />
        </label>
        <label style={label}>
          Password
          <input type="password" name="password" autoComplete="current-password" maxLength={1024}
            value={password} onChange={(e) => setPassword(e.target.value)} style={input} disabled={busy} />
        </label>
        {error && <div role="alert" style={{ fontSize: '13px', color: '#f87171' }}>{error}</div>}
        <button type="submit" disabled={!ready}
          style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px', padding: '10px 14px',
            borderRadius: 'var(--radius-sm)', border: 'none', fontWeight: 700, fontSize: '14px',
            background: 'linear-gradient(135deg, #00f2fe, #4facfe)', color: '#090d16',
            cursor: ready ? 'pointer' : 'not-allowed', opacity: ready ? 1 : 0.5,
          }}>
          <LogIn size={14} /> {busy ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
