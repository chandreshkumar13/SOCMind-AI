import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import AgentActivity from './pages/AgentActivity';
import AuditLog from './pages/AuditLog';
import Settings from './pages/Settings';
import { api, apiPage } from './api';
import { appendPage } from './lib/view.js';

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

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} counts={{ audit: stats ? stats.audit_entries : 0, alerts: stats ? stats.alerts.total : alerts.length, incidents: stats ? stats.incidents.total : (incidents || []).filter((i) => i.status !== 'MERGED').length }} />
      <div className="main-content">
        <Topbar activeTab={activeTab} online={online} />
        <main className="page-wrapper">
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
          {activeTab === 'settings' && <Settings />}
        </main>
      </div>
    </div>
  );
}
