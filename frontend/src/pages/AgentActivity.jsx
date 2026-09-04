import React from 'react';
import { Cpu, CheckCircle2, Terminal, ShieldAlert } from 'lucide-react';

export default function AgentActivity() {
  const agents = [
    {
      name: '1. Triage Agent',
      status: 'Ready',
      role: 'Severity Scoring & Suspicion Rationale',
      metrics: '5 Alerts Triaged',
      log: 'Evaluated raw severity ratings against synthetic attack heuristics. Outputted normalized suspicion scores.'
    },
    {
      name: '2. Correlation Agent',
      status: 'Ready',
      role: 'Duplicate Detection & Incident Grouping',
      metrics: '2 Incidents Correlated',
      log: 'Identified entity overlap between ALT-2026-001 (PowerShell) and ALT-2026-004 (C2 Beacon) on host FINANCE-WKS-042.'
    },
    {
      name: '3. Enrichment Agent',
      status: 'Ready',
      role: 'IOC Threat Intelligence Lookups',
      metrics: '3 IOCs Enriched',
      log: 'Queried mock threat intelligence sources for IP 185.220.101.5 and SHA256 file hashes.'
    },
    {
      name: '4. Investigation Agent',
      status: 'Ready',
      role: 'Log Analysis & Timeline Reconstruction',
      metrics: '4 Events Mapped',
      log: 'Reconstructed attack progression timeline distinguishing verified log events from AI hypotheses.'
    },
    {
      name: '5. Response Agent',
      status: 'Ready',
      role: 'Action Proposals & Human Approval Routing',
      metrics: '2 Recommendations Queued',
      log: 'Formulated host isolation & perimeter blocking proposals. Enforced mandatory human approval check.'
    }
  ];

  return (
    <div>
      <div className="agent-grid" style={{ marginBottom: '24px' }}>
        {agents.map((ag, idx) => (
          <div key={idx} className="glass-card agent-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cpu size={18} color="var(--accent-cyan)" />
                <h3 style={{ fontSize: '15px' }}>{ag.name}</h3>
              </div>
              <span className="badge badge-success">{ag.status}</span>
            </div>

            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
              {ag.role}
            </div>

            <div style={{
              background: 'var(--bg-dark)',
              padding: '10px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)'
            }}>
              <div style={{ color: 'var(--accent-cyan)', marginBottom: '4px', fontWeight: 600 }}>
                Log Snippet:
              </div>
              {ag.log}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
