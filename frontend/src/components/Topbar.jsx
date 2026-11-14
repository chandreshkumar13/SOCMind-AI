import React from 'react';
import { Activity, LogOut, User } from 'lucide-react';
import { identityLabel } from '../lib/session';

/**
 * The top bar. `user` is the signed-in account as returned by the server (or null); `mode` is the server's AUTH_MODE.
 * Nobody is shown as signed in unless the server says so.
 */
export default function Topbar({ activeTab, online, user = null, mode = null, onSignOut = null }) {
  const identity = identityLabel(user, mode);
  const status = online === null ? 'Checking...' : online ? 'Online' : 'Unreachable';
  const color = online === false ? '#f87171' : 'var(--accent-cyan)';
  const titles = {
    dashboard: 'SOC Overview & Metrics',
    alerts: 'Normalized Security Alerts Queue',
    incidents: 'Correlated Incident Candidates & Timelines',
    agents: 'Multi-Agent Autonomous Pipeline Status',
    audit: 'Audit Trail of Agent and Analyst Actions',
    settings: 'Backend Configuration & Safety Boundaries'
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
            <div style={{ fontWeight: 600 }}>{identity.title}</div>
            {identity.subtitle && <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{identity.subtitle}</div>}
          </div>
          {onSignOut && user && (
            <button type="button" onClick={onSignOut} title="End this session"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 10px', marginLeft: '6px',
                borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'transparent',
                color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
              }}>
              <LogOut size={12} /> Sign out
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
