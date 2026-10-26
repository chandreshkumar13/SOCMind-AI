import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  AlertTriangle, 
  FolderGit2, 
  Cpu, 
  Settings,
  ShieldCheck,
  FileText
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, counts = {} }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Security Alerts', icon: AlertTriangle, badge: counts.alerts ? String(counts.alerts) : null },
    { id: 'incidents', label: 'Correlated Incidents', icon: FolderGit2, badge: counts.incidents ? String(counts.incidents) : null },
    { id: 'agents', label: 'Agent Pipeline', icon: Cpu },
    { id: 'audit', label: 'Audit Log', icon: FileText, badge: counts.audit ? String(counts.audit) : null },
    { id: 'settings', label: 'Settings & Config', icon: Settings },
  ];

  return (
    <aside style={{
      width: '260px',
      backgroundColor: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--border-color)',
      display: 'flex',
      flexDirection: 'column',
      padding: '20px 16px'
    }}>
      {/* Brand Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '0 8px 24px 8px',
        borderBottom: '1px solid var(--border-color)'
      }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '8px',
          background: 'linear-gradient(135deg, #00f2fe, #4facfe)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#090d16'
        }}>
          <ShieldAlert size={22} />
        </div>
        <div>
          <h2 style={{ fontSize: '18px', lineHeight: 1.2 }}>
            SOCMind <span className="gradient-text">AI</span>
          </h2>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Threat Copilot v1.0</span>
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={{ flex: 1, marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                background: isActive ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 400,
                cursor: 'pointer',
                transition: 'var(--transition)',
                width: '100%',
                textAlign: 'left'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <Icon size={18} color={isActive ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span style={{
                  fontSize: '11px',
                  padding: '2px 6px',
                  borderRadius: '10px',
                  background: isActive ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.08)',
                  color: isActive ? '#090d16' : 'var(--text-muted)',
                  fontWeight: 700
                }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Safety Notice Footer */}
      <div style={{
        padding: '12px',
        borderRadius: 'var(--radius-sm)',
        background: 'rgba(16, 185, 129, 0.08)',
        border: '1px solid rgba(16, 185, 129, 0.2)',
        display: 'flex',
        alignItems: 'center',
        gap: '10px'
      }}>
        <ShieldCheck size={20} color="#10b981" />
        <div style={{ fontSize: '11px', color: '#6ee7b7' }}>
          <strong>Safety Lock Enabled</strong>
          <div>Human approval required</div>
        </div>
      </div>
    </aside>
  );
}
