import React from 'react';
import { AlertTriangle, ShieldCheck, Zap, Cpu, Activity, Clock } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';

export default function Dashboard({ alerts, setActiveTab }) {
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
            <div className="metric-label">Active Synthetic Alerts</div>
          </div>
        </div>

        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(249, 115, 22, 0.1)', color: '#f97316' }}>
            <Zap size={24} />
          </div>
          <div>
            <div className="metric-value">2</div>
            <div className="metric-label">Correlated Incidents</div>
          </div>
        </div>

        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(0, 242, 254, 0.1)', color: '#00f2fe' }}>
            <Cpu size={24} />
          </div>
          <div>
            <div className="metric-value">5 / 5</div>
            <div className="metric-label">AI Agents Ready</div>
          </div>
        </div>

        <div className="glass-card metric-card">
          <div className="metric-icon" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
            <Clock size={24} />
          </div>
          <div>
            <div className="metric-value">-78%</div>
            <div className="metric-label">Estimated MTTR Reduction</div>
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
                {alerts.slice(0, 4).map((a) => (
                  <tr key={a.id}>
                    <td className="code-font">{a.id}</td>
                    <td style={{ fontWeight: 600 }}>{a.alert_name}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{a.source_system}</td>
                    <td><StatusBadge severity={a.raw_severity} /></td>
                    <td className="code-font">{a.host_name || a.ip_address}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* AI Agent Status Panel */}
        <div className="glass-card">
          <h3 style={{ fontSize: '16px', marginBottom: '16px' }}>Agent Pipeline Status</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[
              { name: '1. Triage Agent', desc: 'Normalized alert severity analysis' },
              { name: '2. Correlation Agent', desc: 'Grouping duplicate/related alerts' },
              { name: '3. Enrichment Agent', desc: 'IOC reputation & threat intel queries' },
              { name: '4. Investigation Agent', desc: 'Forensic log timeline reconstruction' },
              { name: '5. Response Agent', desc: 'Human-in-the-loop action proposals' }
            ].map((agent, i) => (
              <div key={i} style={{
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
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{agent.desc}</div>
                </div>
                <div className="agent-status-active">
                  <div className="status-dot"></div>
                  <span>Ready</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
