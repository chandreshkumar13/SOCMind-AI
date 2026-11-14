import React, { useState, useEffect, useCallback, useRef } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import { ErrorCard, LoadingCard } from './components/StateCards';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import AgentActivity from './pages/AgentActivity';
import AuditLog from './pages/AuditLog';
import Settings from './pages/Settings';
import { api, apiPage, SIGNED_OUT_EVENT, setAuthMode, setCsrfToken, storeToken } from './api';
import { appendPage } from './lib/view.js';
import { signInRequired, signOutOutcome } from './lib/session';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [incidents, setIncidents] = useState(null);
  const [incidentsLoading, setIncidentsLoading] = useState(true);
  const [incidentsError, setIncidentsError] = useState(null);
  const [online, setOnline] = useState(null);
  const [stats, setStats] = useState(null);
  const [alertsTotal, setAlertsTotal] = useState(null);       // matching alerts on the server (X-Total-Count)
  const [incidentsTotal, setIncidentsTotal] = useState(null);
  const [loadingMore, setLoadingMore] = useState(null);       // 'alerts' | 'incidents' while a next page is fetched
  // phase: 'checking' (asking the server whether sign-in is needed), 'signin' (show the sign-in page), 'ready' (show the app).
  // Nothing is loaded from the API until the phase is 'ready'.
  const [auth, setAuth] = useState({ phase: 'checking', mode: null, signInRequired: false, user: null });
  const [signOutError, setSignOutError] = useState('');       // shown when the server did not confirm sign-out
  const accountsRef = useRef(false);
  accountsRef.current = auth.signInRequired;

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await apiPage('/alerts?limit=100');
      setAlerts(page.data);
      setAlertsTotal(page.total);
      setOnline(true);
    } catch (err) {
      console.error('API Error:', err);
      setError(err.message || 'Failed to connect to SOCMind AI Backend');
      setOnline(false);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchIncidents = useCallback(async () => {
    setIncidentsLoading(true);
    setIncidentsError(null);
    try {
      const page = await apiPage('/incidents?limit=100');
      setIncidents(page.data);
      setIncidentsTotal(page.total);
    } catch (err) {
      setIncidentsError(err.message || 'Failed to load incidents');
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  // The next page continues from what is already loaded, so search and filters on the loaded records are kept.
  const loadMoreAlerts = useCallback(async () => {
    setLoadingMore('alerts');
    try {
      const page = await apiPage(`/alerts?limit=100&offset=${alerts.length}`);
      setAlerts((prev) => appendPage(prev, page.data));
      setAlertsTotal(page.total);
    } catch (err) {
      setError(err.message || 'Failed to load more alerts');
    } finally {
      setLoadingMore(null);
    }
  }, [alerts.length]);

  const loadMoreIncidents = useCallback(async () => {
    setLoadingMore('incidents');
    try {
      const page = await apiPage(`/incidents?limit=100&offset=${(incidents || []).length}`);
      setIncidents((prev) => appendPage(prev || [], page.data));
      setIncidentsTotal(page.total);
    } catch (err) {
      setIncidentsError(err.message || 'Failed to load more incidents');
    } finally {
      setLoadingMore(null);
    }
  }, [incidents]);

  const fetchStats = useCallback(async () => {
    try {
      setStats(await api('/stats'));
    } catch {
      setStats(null);   // pages fall back to the loaded lists
    }
  }, []);

  const refreshAll = useCallback(() => {
    fetchAlerts();
    fetchIncidents();
    fetchStats();
  }, [fetchAlerts, fetchIncidents, fetchStats]);

  // Removes everything the previous session could see. Used on sign-out and when a session ends.
  const clearSessionData = useCallback(() => {
    setAlerts([]);
    setAlertsTotal(null);
    setIncidents(null);
    setIncidentsTotal(null);
    setStats(null);
    setError(null);
    setIncidentsError(null);
    setOnline(null);
  }, []);

  // Sample data is loaded only when the analyst asks for it, never silently on page load
  const seedSampleAlerts = useCallback(async () => {
    try {
      await api('/alerts/seed', { method: 'POST' });
    } catch (err) {
      setError(err.message);
    }
    await fetchAlerts();
    fetchStats();
  }, [fetchAlerts, fetchStats]);

  // Before anything else: find out whether sign-in is required, and if so whether this browser already has a session.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      let status;
      try {
        status = await api('/auth/status');
      } catch {
        // the server cannot be reached: show the app, which reports that in its own way
        if (!cancelled) setAuth({ phase: 'ready', mode: null, signInRequired: false, user: null });
        return;
      }
      // The mode is known before any protected request. In accounts mode a bearer token left in this browser is removed and
      // never used: the session cookie is the only credential there.
      setAuthMode(status.mode);
      if (status.mode === 'accounts') storeToken('');
      if (!signInRequired(status)) {
        if (!cancelled) setAuth({ phase: 'ready', mode: status.mode, signInRequired: false, user: null });
        return;
      }
      try {
        const me = await api('/auth/me');
        if (cancelled) return;
        if (me.authenticated && me.mode === 'accounts') {
          setCsrfToken(me.csrf_token);
          setAuth({ phase: 'ready', mode: status.mode, signInRequired: true, user: me });
        } else {
          setAuth({ phase: 'signin', mode: status.mode, signInRequired: true, user: null });
        }
      } catch {
        if (!cancelled) setAuth({ phase: 'signin', mode: status.mode, signInRequired: true, user: null });
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // A request refused with 401 means the session has ended: back to the sign-in page, with the data removed.
  // Token and demo modes keep their own error messages, so they are left alone.
  useEffect(() => {
    const onSignedOut = () => {
      if (!accountsRef.current) return;
      setCsrfToken('');
      clearSessionData();
      setAuth((current) => ({ ...current, phase: 'signin', user: null }));
    };
    window.addEventListener(SIGNED_OUT_EVENT, onSignedOut);
    return () => window.removeEventListener(SIGNED_OUT_EVENT, onSignedOut);
  }, [clearSessionData]);

  // Data is loaded only once the page is allowed to show it.
  useEffect(() => {
    if (auth.phase === 'ready') refreshAll();
  }, [refreshAll, auth.phase]);

  const handleSignedIn = useCallback((session) => {
    setSignOutError('');
    setAuth({ phase: 'ready', mode: 'accounts', signInRequired: true, user: session });
  }, []);

  // Only a confirmed revocation (or a session that had already ended on the server) clears the page. Anything else keeps the user
  // signed in, shows why, and offers a retry, so a failed sign-out is never reported as a successful one.
  const signOut = useCallback(async () => {
    setSignOutError('');
    try {
      await api('/auth/logout', { method: 'POST' });
    } catch (err) {
      const outcome = signOutOutcome(err);
      if (!outcome.revoked && !outcome.endedElsewhere) {
        setSignOutError(outcome.message);
        return;
      }
    }
    setCsrfToken('');
    clearSessionData();
    setAuth((current) => ({ ...current, phase: 'signin', user: null }));
  }, [clearSessionData]);

  if (auth.phase === 'checking') {
    return (
      <div className="app-container" style={{ padding: '40px' }}>
        <LoadingCard>Checking your session...</LoadingCard>
      </div>
    );
  }
  if (auth.phase === 'signin') return <Login onSignedIn={handleSignedIn} />;

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} counts={{ audit: stats ? stats.audit_entries : 0, alerts: stats ? stats.alerts.total : alerts.length, incidents: stats ? stats.incidents.total : (incidents || []).filter((i) => i.status !== 'MERGED').length }} />
      <div className="main-content">
        <Topbar activeTab={activeTab} online={online} user={auth.user} mode={auth.mode} onSignOut={auth.signInRequired ? signOut : null} />
        <main className="page-wrapper">
          {signOutError && <ErrorCard title="Sign-out did not complete" message={signOutError} onRetry={signOut} />}
          {activeTab === 'dashboard' && <Dashboard alerts={alerts} incidents={incidents} stats={stats} setActiveTab={setActiveTab} />}
          {activeTab === 'alerts' && (
            <Alerts
              alerts={alerts}
              loading={loading}
              error={error}
              refreshAlerts={refreshAll}
              seedSampleAlerts={seedSampleAlerts}
              totalAlerts={stats ? stats.alerts.total : undefined}
              alertsTotal={alertsTotal}
              loadMoreAlerts={loadMoreAlerts}
              loadingMore={loadingMore === 'alerts'}
            />
          )}
          {activeTab === 'incidents' && (
            <Incidents
              incidents={incidents}
              loading={incidentsLoading}
              error={incidentsError}
              refresh={fetchIncidents}
              refreshAlerts={refreshAll}
              incidentsTotal={incidentsTotal}
              loadMoreIncidents={loadMoreIncidents}
              loadingMore={loadingMore === 'incidents'}
            />
          )}
          {activeTab === 'agents' && <AgentActivity refreshAlerts={refreshAll} />}
          {activeTab === 'audit' && <AuditLog />}
          {activeTab === 'settings' && <Settings authMode={auth.mode} account={auth.user} />}
        </main>
      </div>
    </div>
  );
}
