import React from 'react';
import { AlertTriangle, Zap, Cpu, UserCheck } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import { ErrorCard } from '../components/StateCards';
import { api } from '../api';
import useAsync from '../lib/useAsync';

export default function Dashboard({ alerts, incidents, setActiveTab }) {
  const agents = useAsync(() => api('/agents'), []);
  const open = (incidents || []).filter((i) => i.status !== 'MERGED');
  const awaiting = open.filter((i) => i.status === 'RESPONSE_PROPOSED' && i.human_approval_status === 'PENDING').length;
  const agentList = agents.data || [];
  const healthy = agentList.filter((a) => a.status === 'READY' && a.failures === 0).length;

  return (
    <div>
      {/* Top Welcome Banner */}
      <div className="glass-card" style={{ marginBottom: '24px', background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.08), rgba(124, 58, 237, 0.05))' }}>
        <h2 style={{ fontSize: '22px', marginBottom: '8px' }}>
          Autonomous Threat Triage & Incident Copilot
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px', maxWidth: '750px' }}>
          SOCMind AI assists security analysts by ingesting alerts, running multi-agent correlation and threat-intelligence enrichment, and recommending human-in-the-loop remediation actions.
        </p>
      </div>

      {/* Metrics Grid */}
      <div className="metrics-grid">
        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444' }}>
            <AlertTriangle size={24} />
          </div>
          <div>
            <div className="metric-value">{alerts.length}</div>
            <div className="metric-label">Alerts In Queue</div>
          </div>
        </div>

        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(249, 115, 22, 0.1)', color: '#f97316' }}>
            <Zap size={24} />
          </div>
          <div>
            <div className="metric-value">{open.length}</div>
            <div className="metric-label">Correlated Incidents</div>
          </div>
        </div>

        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(0, 242, 254, 0.1)', color: '#00f2fe' }}>
            <Cpu size={24} />
          </div>
          <div>
            <div className="metric-value">{agents.data ? `${healthy} / ${agentList.length}` : '–'}</div>
            <div className="metric-label">Agents Ready (no failures)</div>
          </div>
        </div>

        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
            <UserCheck size={24} />
          </div>
          <div>
            <div className="metric-value">{awaiting}</div>
            <div className="metric-label">Awaiting Human Review</div>
          </div>
        </div>
      </div>

      {/* Dashboard Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>
        {/* Recent Alerts Feed */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ fontSize: '16px' }}>Recent Ingested Security Alerts</h3>
            <button 
              onClick={() => setActiveTab('alerts')}
              style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontSize: '13px', fontWeight: 600 }}
            >
              View All Queue →
            </button>
          </div>

          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Alert Name</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Host / IP</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 && (
                  <tr><td colSpan="5" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>No alerts ingested yet.</td></tr>
                )}
                {alerts.slice(0, 4).map((a) => (
                  <tr key={a.id}>
                    <td className="code-font">{a.id}</td>
                    <td style={{ fontWeight: 600 }}>{a.alert_title}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{a.source}</td>
                    <td><StatusBadge severity={a.severity} /></td>
                    <td className="code-font">{a.host || a.source_ip || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* AI Agent Status Panel */}
        <div className="glass-card">
          <h3 style={{ fontSize: '16px', marginBottom: '16px' }}>Agent Pipeline Status</h3>
          {agents.error && <ErrorCard title="Agent status unavailable" message={agents.error} onRetry={agents.reload} />}
          {agents.loading && !agents.data && <div style={{ fontSize: '12px', color: 'var(--accent-cyan)' }}>Loading agent activity...</div>}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {agentList.map((agent) => (
              <div key={agent.name} style={{
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid var(--border-color)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600 }}>{agent.name}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{agent.total_actions} action(s) logged{agent.last_action ? ` · last: ${agent.last_action}` : ''}</div>
                </div>
                <div className="agent-status-active">
                  <div className="status-dot"></div>
                  <span>{agent.failures > 0 ? `${agent.failures} failed` : 'Ready'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
