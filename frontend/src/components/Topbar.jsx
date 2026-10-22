import React from 'react';
import { Activity, Bell, User, Cpu } from 'lucide-react';

export default function Topbar({ activeTab, online }) {
  const status = online === null ? 'Checking...' : online ? 'Online' : 'Unreachable';
  const color = online === false ? '#f87171' : 'var(--accent-cyan)';
  const titles = {
    dashboard: 'SOC Overview & Metrics',
    alerts: 'Normalized Security Alerts Queue',
    incidents: 'Correlated Incident Candidates & Timelines',
    agents: 'Multi-Agent Autonomous Pipeline Status',
    settings: 'System Configuration & LLM Provider'
  };

  return (
    <header style={{
      height: '64px',
      borderBottom: '1px solid var(--border-color)',
      backgroundColor: 'var(--bg-card)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 32px'
    }}>
      <div>
        <h1 style={{ fontSize: '20px', color: '#ffffff' }}>
          {titles[activeTab] || 'SOCMind AI'}
        </h1>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Academic Team 150 Workspace
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        {/* Backend System Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 12px',
          borderRadius: 'var(--radius-sm)',
          background: 'rgba(0, 242, 254, 0.08)',
          border: '1px solid rgba(0, 242, 254, 0.2)',
          fontSize: '12px',
          color
        }}>
          <Activity size={14} className={online ? 'pulse' : ''} />
          <span>Backend API: {status}</span>
        </div>

        {/* User Profile */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          paddingLeft: '16px',
          borderLeft: '1px solid var(--border-color)'
        }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '50%',
            background: 'var(--bg-card-hover)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-main)'
          }}>
            <User size={16} />
          </div>
          <div style={{ fontSize: '13px' }}>
            <div style={{ fontWeight: 600 }}>Chandresh Kumar</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Lead SOC Analyst</div>
          </div>
        </div>
      </div>
    </header>
  );
}
