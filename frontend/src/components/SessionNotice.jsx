import React, { useEffect, useRef, useState } from 'react';
import { ActionButton } from './StateCards';
import { api, getLastActivity } from '../api';
import { absoluteDeadline, sessionWarning, sessionWarningMessage, warningCanBeExtended } from '../lib/session';

/**
 * Warns before an account session ends (accounts mode only; the page shows it only to a signed-in account).
 *  - Two minutes before the idle timeout: "Your session will end in 2 minutes due to inactivity", with a Stay signed in button that
 *    sends one light authenticated request (GET /auth/me), which the server counts as use.
 *  - Five minutes before the absolute limit: a notice only, because nothing extends that limit.
 * The timing is decided by sessionWarning (lib/session.js). When the time has passed, one request is sent; if the server says the
 * session is over, the usual 401 handling in api.js returns the page to the sign-in screen.
 * `now` and `lastActivityAt` can be passed in for tests; the page leaves them out.
 */
export default function SessionNotice({ session, now: nowOverride, lastActivityAt: activityOverride }) {
  const [tick, setTick] = useState(() => Date.now());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const probed = useRef(false);

  useEffect(() => {
    const id = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const warning = sessionWarning({
    now: nowOverride === undefined ? tick : nowOverride,
    lastActivityAt: activityOverride === undefined ? getLastActivity() : activityOverride,
    idleTimeoutMinutes: session && session.idle_timeout_minutes,
    absoluteDeadlineAt: absoluteDeadline(session, session && session.receivedAt),
  });

  useEffect(() => {
    if (warning.kind === 'expired' && !probed.current) {
      probed.current = true;
      api('/auth/me').catch(() => { /* a 401 is handled in api.js; anything else leaves the notice showing */ });
    }
    if (warning.kind !== 'expired') probed.current = false;
  }, [warning.kind]);

  if (!warning.kind) return null;

  const stay = async () => {
    setBusy(true);
    setError('');
    try {
      await api('/auth/me');
    } catch (err) {
      setError(err.message || 'Could not reach the server.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div role="alert" className="glass-card"
      style={{ marginBottom: '16px', padding: '14px 18px', borderLeft: '4px solid #f59e0b', display: 'flex', gap: '16px', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
      <div style={{ fontSize: '13px' }}>
        <strong>{sessionWarningMessage(warning)}</strong>
        {error && <div style={{ color: '#f87171', marginTop: '4px' }}>{error}</div>}
      </div>
      {warningCanBeExtended(warning) && <ActionButton busy={busy} onClick={stay}>Stay signed in</ActionButton>}
    </div>
  );
}
