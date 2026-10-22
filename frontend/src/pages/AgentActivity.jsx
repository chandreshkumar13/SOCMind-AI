import React, { useState } from 'react';
import { Cpu, Play, RefreshCw } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import PipelineRunReport from '../components/PipelineRunReport';
import { ActionButton, EmptyCard, ErrorCard, LoadingCard } from '../components/StateCards';
import { api } from '../api';
import useAsync from '../lib/useAsync';

export default function AgentActivity({ refreshAlerts }) {
  const agents = useAsync(() => api('/agents'), []);
  const runs = useAsync(() => api('/pipeline/runs?limit=5'), []);
  const [busy, setBusy] = useState(false);
  const [runError, setRunError] = useState(null);

  const reloadAll = () => { agents.reload(); runs.reload(); };

  const runPipeline = async () => {
    setBusy(true);
    setRunError(null);
    try {
      await api('/pipeline/run', { method: 'POST' });
    } catch (err) {
      setRunError(err.message);
    } finally {
      setBusy(false);
      reloadAll();
      if (refreshAlerts) refreshAlerts();
    }
  };

  return (
    <div>
      <div className="glass-card" style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        <div style={{ fontSize: '13px' }}>
          Counts below come from the audit log: what each agent actually did, not a status label.
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Triage → Enrichment → Correlation → Investigation → Response. Approval is always a separate human step.</div>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <ActionButton busy={busy} onClick={runPipeline}><Play size={12} style={{ verticalAlign: '-2px' }} /> Run full pipeline</ActionButton>
          <ActionButton variant="ghost" onClick={reloadAll}><RefreshCw size={12} style={{ verticalAlign: '-2px' }} /> Refresh</ActionButton>
        </div>
      </div>

      {runError && <ErrorCard title="Pipeline run failed" message={runError} />}

      {agents.loading && !agents.data && <LoadingCard>Loading agent activity...</LoadingCard>}
      {agents.error && <ErrorCard title="Could not load agent activity" message={agents.error} onRetry={agents.reload} />}
      {agents.data && (
        <div className="agent-grid" style={{ marginBottom: '24px' }}>
          {agents.data.map((ag) => (
            <div key={ag.name} className="glass-card agent-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Cpu size={18} color="var(--accent-cyan)" />
                  <h3 style={{ fontSize: '15px' }}>{ag.name}</h3>
                </div>
                <StatusBadge severity={ag.failures > 0 ? 'high' : 'success'} label={ag.failures > 0 ? `${ag.failures} failure(s)` : ag.status} />
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>{ag.role}</div>
              <div style={{ background: 'var(--bg-dark)', padding: '10px', borderRadius: 'var(--radius-sm)', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                <div style={{ color: 'var(--accent-cyan)', marginBottom: '4px', fontWeight: 600 }}>Recorded activity</div>
                <div>Actions logged: {ag.total_actions}</div>
                <div>Last action: {ag.last_action || 'none yet'}{ag.last_target ? ` (${ag.last_target})` : ''}</div>
                <div>Last run: {ag.last_run_at ? `${ag.last_run_at.replace('T', ' ').slice(0, 19)} UTC` : 'never'}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      <h3 style={{ fontSize: '16px', margin: '8px 0 12px' }}>Recent pipeline runs</h3>
      {runs.loading && !runs.data && <LoadingCard>Loading runs...</LoadingCard>}
      {runs.error && <ErrorCard title="Could not load pipeline runs" message={runs.error} onRetry={runs.reload} />}
      {runs.data && runs.data.length === 0 && <EmptyCard title="No pipeline runs yet">Use “Run full pipeline” to process the alerts in the database.</EmptyCard>}
      {(runs.data || []).map((run) => <PipelineRunReport key={run.run_id} run={run} />)}
    </div>
  );
}
