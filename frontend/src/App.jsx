import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import AgentActivity from './pages/AgentActivity';
import Settings from './pages/Settings';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      // Seed initial data if DB is empty
      await fetch('http://localhost:8000/api/v1/alerts/seed', { method: 'POST' }).catch(() => {});

      const res = await fetch('http://localhost:8000/api/v1/alerts?limit=100');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch security alerts`);
      const data = await res.json();
      setAlerts(data);
    } catch (err) {
      console.error('API Error:', err);
      setError(err.message || 'Failed to connect to SOCMind AI Backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="main-content">
        <Topbar activeTab={activeTab} />
        <main className="page-wrapper">
          {activeTab === 'dashboard' && <Dashboard alerts={alerts} setActiveTab={setActiveTab} />}
          {activeTab === 'alerts' && (
            <Alerts 
              alerts={alerts} 
              loading={loading} 
              error={error} 
              refreshAlerts={fetchAlerts} 
            />
          )}
          {activeTab === 'incidents' && <Incidents />}
          {activeTab === 'agents' && <AgentActivity />}
          {activeTab === 'settings' && <Settings />}
        </main>
      </div>
    </div>
  );
}
