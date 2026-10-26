import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import AgentActivity from './pages/AgentActivity';
import AuditLog from './pages/AuditLog';
import Settings from './pages/Settings';
import { api } from './api';

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

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setAlerts(await api('/alerts?limit=100'));
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
      setIncidents(await api('/incidents?limit=100'));
    } catch (err) {
      setIncidentsError(err.message || 'Failed to load incidents');
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

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
            />
          )}
          {activeTab === 'incidents' && (
            <Incidents
              incidents={incidents}
              loading={incidentsLoading}
              error={incidentsError}
              refresh={fetchIncidents}
              refreshAlerts={refreshAll}
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
