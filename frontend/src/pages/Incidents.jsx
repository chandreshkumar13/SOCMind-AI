import React from 'react';
import { FolderGit2, ShieldCheck, AlertCircle, ArrowRight, UserCheck } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';

export default function Incidents() {
  const sampleIncidents = [
    {
      id: 'INC-2026-089',
      title: 'Suspicious Encoded Execution & C2 Beaconing on FINANCE-WKS-042',
      severity: 'Critical',
      status: 'Investigation Complete',
      alerts_count: 2,
      correlated_alerts: ['ALT-2026-001', 'ALT-2026-004'],
      ai_summary: 'Correlated Encoded PowerShell command execution (ALT-2026-001) with subsequent outbound HTTPS network beaconing to suspicious external C2 IP 185.220.101.5 (ALT-2026-004).',
      recommendation: 'Isolate host FINANCE-WKS-042 (192.168.10.42) from corporate subnet and block IP 185.220.101.5 at perimeter firewall.',
      human_approval: 'Pending Analyst Sign-off'
    },
    {
      id: 'INC-2026-090',
      title: 'Potential Ransomware Bulk File Renaming Activity',
      severity: 'High',
      status: 'Triage Pending',
      alerts_count: 1,
      correlated_alerts: ['ALT-2026-005'],
      ai_summary: 'Detected rapid file renaming event on HR-FILE-SERVER by user s.administrator matching ransomware behavior heuristic.',
      recommendation: 'Terminate process encryptor.exe and revoke user s.administrator Active Directory token.',
      human_approval: 'Pending Analyst Sign-off'
    }
  ];

  return (
    <div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {sampleIncidents.map(inc => (
          <div key={inc.id} className="glass-card" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                  <span className="code-font" style={{ fontSize: '14px', fontWeight: 700 }}>{inc.id}</span>
                  <StatusBadge severity={inc.severity} />
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{inc.alerts_count} Alerts Correlated</span>
                </div>
                <h3 style={{ fontSize: '18px' }}>{inc.title}</h3>
              </div>

              <div style={{
                padding: '4px 12px',
                borderRadius: '9999px',
                background: 'rgba(234, 179, 8, 0.1)',
                border: '1px solid rgba(234, 179, 8, 0.3)',
                color: '#fde047',
                fontSize: '12px',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}>
                <UserCheck size={14} />
                {inc.human_approval}
              </div>
            </div>

            {/* AI Summary */}
            <div style={{
              background: 'rgba(0, 0, 0, 0.2)',
              padding: '12px 16px',
              borderRadius: 'var(--radius-sm)',
              marginBottom: '16px',
              border: '1px solid var(--border-color)'
            }}>
              <strong style={{ fontSize: '12px', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                🤖 AI Copilot Incident Summary:
              </strong>
              <p style={{ fontSize: '13px', color: 'var(--text-main)', marginTop: '4px' }}>
                {inc.ai_summary}
              </p>
            </div>

            {/* Response Action Recommendation & Human Approval Gate */}
            <div style={{
              background: 'rgba(124, 58, 237, 0.08)',
              padding: '14px 16px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid rgba(124, 58, 237, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '16px'
            }}>
              <div>
                <strong style={{ fontSize: '12px', color: '#a78bfa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  🛡️ Recommended Action (Requires Analyst Approval):
                </strong>
                <div style={{ fontSize: '13px', fontWeight: 600, marginTop: '2px' }}>
                  {inc.recommendation}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button 
                  onClick={() => alert(`Simulated Action Approved for ${inc.id}. Audit log recorded.`)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 'var(--radius-sm)',
                    border: 'none',
                    background: '#10b981',
                    color: '#ffffff',
                    fontWeight: 700,
                    fontSize: '12px',
                    cursor: 'pointer'
                  }}
                >
                  Approve Action
                </button>
                <button 
                  onClick={() => alert(`Action Rejected for ${inc.id}.`)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-color)',
                    background: 'transparent',
                    color: 'var(--text-muted)',
                    fontSize: '12px',
                    cursor: 'pointer'
                  }}
                >
                  Reject / Override
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
