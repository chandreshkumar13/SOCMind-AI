import React from 'react';
import StatusBadge from './StatusBadge';
import { runBadgeKey, stageBadgeKey, summarizeRun } from '../lib/view';

/** Stage-by-stage report of one pipeline run (the object returned by POST /pipeline/run or GET /pipeline/runs). */
export default function PipelineRunReport({ run }) {
  if (!run) return null;
  return (
    <div className="glass-card" style={{ marginBottom: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <h3 style={{ fontSize: '15px' }}>Pipeline run <span className="code-font">{run.run_id}</span></h3>
          <StatusBadge severity={runBadgeKey(run.outcome)} label={String(run.outcome || run.status).toUpperCase()} />
        </div>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          {run.started_at ? `${run.started_at.replace('T', ' ').slice(0, 19)} UTC` : ''} · {run.duration_ms} ms
        </span>
      </div>
      <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '12px' }}>{summarizeRun(run)}. {run.message || ''}</div>

      {(run.warnings || []).length > 0 && (
        <ul style={{ margin: '0 0 12px 18px', fontSize: '12px', color: '#fde047' }}>
          {run.warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}

      <div className="table-container">
        <table className="cyber-table">
          <thead>
            <tr><th>Stage</th><th>Status</th><th>Processed</th><th>Skipped</th><th>Time</th><th>Errors</th></tr>
          </thead>
          <tbody>
            {(run.stages || []).map((s) => (
              <tr key={s.agent}>
                <td style={{ fontWeight: 600 }}>{s.agent}</td>
                <td><StatusBadge severity={stageBadgeKey(s.status)} label={s.status} /></td>
                <td className="code-font">{s.processed}</td>
                <td className="code-font">{s.skipped ?? 0}</td>
                <td className="code-font">{s.duration_ms} ms</td>
                <td style={{ fontSize: '12px', color: s.errors && s.errors.length ? '#f87171' : 'var(--text-muted)' }}>
                  {s.errors && s.errors.length ? s.errors.slice(0, 3).join(' | ') : 'none'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '10px' }}>
        Incidents awaiting human review: <strong>{run.incidents_awaiting_human_review}</strong>. The pipeline only proposes actions; it never executes them.
      </div>
    </div>
  );
}
