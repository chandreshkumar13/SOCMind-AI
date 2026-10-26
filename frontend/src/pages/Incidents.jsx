import React, { useState } from 'react';
import { UserCheck, RefreshCw, Play, GitMerge } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import PipelineRunReport from '../components/PipelineRunReport';
import { ActionButton, EmptyCard, ErrorCard, LoadingCard } from '../components/StateCards';
import { api } from '../api';
import useAsync from '../lib/useAsync';
import { formatUtc, groupFindings, reviewState, simulationState, statusLabel } from '../lib/view';

const sectionTitle = { fontSize: '12px', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700, marginBottom: '8px' };
const panel = { background: 'rgba(0, 0, 0, 0.2)', padding: '12px 16px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '14px' };
const muted = { fontSize: '12px', color: 'var(--text-muted)' };

function Tag({ children, color = 'var(--text-muted)' }) {
  return <span style={{ fontSize: '10px', fontWeight: 700, padding: '1px 6px', borderRadius: '4px', border: `1px solid ${color}`, color, marginRight: '8px' }}>{children}</span>;
}

export function Correlation({ correlation }) {
  if (!correlation) return null;
  const shared = Object.entries(correlation.shared_entities || {});
  return (
    <div style={panel}>
      <div style={sectionTitle}>Why these alerts are grouped</div>
      <ul style={{ margin: '0 0 8px 18px', fontSize: '13px' }}>
        {(correlation.reasons || []).map((r, i) => <li key={i}>{r}</li>)}
      </ul>
      <div style={muted}>
        Confidence: <strong>{correlation.confidence}</strong> · window {correlation.window_hours} h · {formatUtc(correlation.first_seen)} → {formatUtc(correlation.last_seen)}
        {shared.length > 0 && <> · shared: {shared.map(([k, v]) => `${k.replace('_', ' ')} ${v.join(', ')}`).join('; ')}</>}
      </div>
    </div>
  );
}

export function CorrelatedAlerts({ alerts }) {
  return (
    <div style={panel}>
      <div style={sectionTitle}>Correlated alerts ({alerts.length})</div>
      <div className="table-container">
        <table className="cyber-table">
          <thead><tr><th>ID</th><th>Time</th><th>Title</th><th>Severity</th><th>Host</th><th>Triage</th></tr></thead>
          <tbody>
            {alerts.map((a) => {
              const t = a.normalized_data && a.normalized_data.triage;
              return (
                <tr key={a.id}>
                  <td className="code-font">{a.id}</td>
                  <td style={{ fontSize: '12px' }}>{formatUtc(a.timestamp)}</td>
                  <td style={{ fontWeight: 600 }}>{a.alert_title}</td>
                  <td><StatusBadge severity={a.severity} /></td>
                  <td className="code-font">{a.host || 'N/A'}</td>
                  <td style={{ fontSize: '12px' }}>{t ? `${t.suspicion_score}/100 (${t.priority})` : 'not triaged'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Investigation({ inv }) {
  if (!inv) return <div style={{ ...panel, ...muted }}>Not investigated yet.</div>;
  const groups = groupFindings(inv.findings);
  const entityLine = (label, items) => items && items.length > 0 && <div style={muted}><strong>{label}:</strong> <span className="code-font">{items.join(', ')}</span></div>;
  return (
    <>
      <div style={panel}>
        <div style={sectionTitle}>Investigation summary</div>
        <p style={{ fontSize: '13px' }}>{inv.summary}</p>
        <div style={{ ...muted, marginTop: '8px' }}>
          Evidence strength: <strong>{inv.evidence_strength}</strong> · {inv.log_records_used} log record(s) used · times are UTC
        </div>
        <div style={{ marginTop: '8px' }}>
          {entityLine('Hosts', inv.entities.hosts)}{entityLine('Users', inv.entities.users)}{entityLine('IPs', inv.entities.ips)}
          {entityLine('Hashes', (inv.entities.hashes || []).map((h) => `${h.slice(0, 16)}...`))}{entityLine('Domains (heuristic)', inv.entities.domains)}
        </div>
        {inv.log_source && (
          <div style={{ ...muted, marginTop: '8px' }}>Log source: <span className="code-font">{inv.log_source.path}</span> — {inv.log_source.note}</div>
        )}
        {(inv.limitations || []).length > 0 && (
          <ul style={{ margin: '10px 0 0 18px', fontSize: '12px', color: '#fde047' }}>
            {inv.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        )}
      </div>

      <div style={panel}>
        <div style={sectionTitle}>Timeline ({inv.timeline.length} events)</div>
        {inv.timeline.length === 0 && <div style={muted}>No events.</div>}
        {inv.timeline.map((e, i) => (
          <div key={i} style={{ display: 'flex', gap: '10px', fontSize: '13px', padding: '4px 0', borderBottom: '1px solid var(--border-color)' }}>
            <span className="code-font" style={{ minWidth: '170px', color: 'var(--text-muted)' }}>{formatUtc(e.time)}</span>
            <span><Tag color={e.type === 'alert' ? '#f97316' : '#4facfe'}>{e.type.toUpperCase()}</Tag>{e.description} <span style={muted}>({e.ref}{e.host ? `, ${e.host}` : ''})</span></span>
          </div>
        ))}
      </div>

      <div style={panel}>
        <div style={sectionTitle}>Verified facts ({groups.verified.length})</div>
        <div style={{ ...muted, marginBottom: '6px' }}>Taken directly from stored alerts, triage results, correlation records and log records.</div>
        {groups.verified.map((f, i) => <div key={i} style={{ fontSize: '13px', padding: '3px 0' }}>• {f.statement}</div>)}
      </div>

      {groups.mock_intel.length > 0 && (
        <div style={{ ...panel, borderColor: 'rgba(234, 179, 8, 0.4)' }}>
          <div style={{ ...sectionTitle, color: '#fde047' }}>Mock threat intelligence — unverified ({groups.mock_intel.length})</div>
          <div style={{ ...muted, marginBottom: '6px' }}>From the local mock intelligence tool. This is not confirmed real-world intelligence.</div>
          {groups.mock_intel.map((f, i) => <div key={i} style={{ fontSize: '13px', padding: '3px 0' }}>• {f.statement}</div>)}
        </div>
      )}

      {groups.hypothesis.length > 0 && (
        <div style={{ ...panel, borderColor: 'rgba(124, 58, 237, 0.4)' }}>
          <div style={{ ...sectionTitle, color: '#a78bfa' }}>Hypotheses — not confirmed ({groups.hypothesis.length})</div>
          <div style={{ ...muted, marginBottom: '6px' }}>Inferences from keyword rules. An analyst must confirm them.</div>
          {groups.hypothesis.map((f, i) => (
            <div key={i} style={{ fontSize: '13px', padding: '4px 0' }}>
              <Tag color="#a78bfa">{f.technique}</Tag><strong>{f.technique_name}</strong> <span style={muted}>confidence: {f.confidence}</span>
              <div>{f.statement}</div>
              <div style={muted}>Basis: {(f.basis || []).join(', ')}</div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

export function Recommendations({ recs, response }) {
  if (!recs || recs.length === 0) return <div style={{ ...panel, ...muted }}>No recommendations yet.</div>;
  const list = (items) => (items && items.length ? items.join(' · ') : 'none');
  return (
    <div style={{ ...panel, borderColor: 'rgba(124, 58, 237, 0.3)' }}>
      <div style={{ ...sectionTitle, color: '#a78bfa' }}>Proposed response actions ({recs.length})</div>
      <div style={{ ...muted, marginBottom: '10px' }}>
        {response && response.note} Mode: <strong>{response && response.execution_mode}</strong>. Evidence strength: <strong>{response && response.evidence_strength}</strong>.
      </div>
      {recs.map((r) => (
        <div key={r.id} style={{ padding: '10px 12px', marginBottom: '10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.02)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
            <div style={{ fontWeight: 600, fontSize: '14px' }}>{r.id} · {r.action}</div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <StatusBadge severity={r.impact === 'HIGH' ? 'high' : r.impact === 'MEDIUM' ? 'medium' : 'low'} label={`Impact ${r.impact}`} />
              <StatusBadge severity={String(r.status).toLowerCase()} label={r.status} />
              <StatusBadge severity="low" label={r.executed ? 'EXECUTED' : 'NOT EXECUTED'} />
              <StatusBadge severity={r.simulation_status === 'SIMULATED' ? 'medium' : 'low'} label={`Simulation: ${r.simulation_status || 'NOT_RUN'}`} />
            </div>
          </div>
          <div style={{ fontSize: '12px', marginTop: '6px' }}>{r.justification}</div>
          <div style={{ ...muted, marginTop: '6px', lineHeight: 1.6 }}>
            <div><strong>Category:</strong> {String(r.category).replace('_', ' ')} · <strong>Target:</strong> {r.target || 'n/a'}</div>
            <div><strong>Expected benefit:</strong> {r.expected_benefit}</div>
            <div><strong>Operational impact:</strong> {r.operational_impact}</div>
            <div><strong>Risk if wrong:</strong> {r.risk_if_wrong}</div>
            <div><strong>Required approvals:</strong> {list(r.required_approvals)}</div>
            <div><strong>Preconditions:</strong> {list(r.preconditions)}</div>
            <div><strong>Validation:</strong> {list(r.validation_steps)}</div>
            <div><strong>Rollback:</strong> {r.rollback} {r.reversible ? '' : '(not reversible)'}</div>
            <div><strong>Evidence:</strong> {list(r.supporting_evidence)}{r.related_techniques && r.related_techniques.length ? ` · techniques (hypotheses): ${r.related_techniques.join(', ')}` : ''}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function Review({ incident, onDecide, busy }) {
  const [reviewer, setReviewer] = useState('');
  const [reason, setReason] = useState('');
  const state = reviewState(incident);
  const review = (incident.details || {}).review;
  const input = { padding: '8px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px' };
  return (
    <div style={{ ...panel, display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div style={sectionTitle}>Human approval</div>
      {review && (
        <div style={{ fontSize: '13px' }}>
          <StatusBadge severity={review.decision.toLowerCase()} label={review.decision} /> by <strong>{review.reviewer}</strong> at {formatUtc(review.reviewed_at)}
          {review.reason && <> — “{review.reason}”</>}
          <div style={muted}>{review.execution}</div>
        </div>
      )}
      {!state.canReview && <div style={muted}>{state.reason}</div>}
      {state.canReview && (
        <>
          <div style={muted}>Recording a decision only stores it with your name in the audit log. SOCMind AI executes nothing.</div>
          <input style={input} placeholder="Your name (required)" value={reviewer} onChange={(e) => setReviewer(e.target.value)} maxLength={100} />
          <input style={input} placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
          <div style={{ display: 'flex', gap: '10px' }}>
            <ActionButton variant="approve" busy={busy} disabled={!reviewer.trim()} onClick={() => onDecide('approve', reviewer.trim(), reason.trim())}>Approve proposal</ActionButton>
            <ActionButton variant="danger" busy={busy} disabled={!reviewer.trim()} onClick={() => onDecide('reject', reviewer.trim(), reason.trim())}>Reject proposal</ActionButton>
          </div>
        </>
      )}
    </div>
  );
}

export function Simulation({ incident, onSimulate, busy }) {
  const [actor, setActor] = useState('');
  const state = simulationState(incident);
  const sim = (incident.details || {}).simulation;
  const input = { padding: '8px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px' };
  if (incident.human_approval_status !== 'APPROVED' && !sim) return null;
  return (
    <div style={{ ...panel, display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div style={sectionTitle}>Response simulation</div>
      {sim && (
        <div style={{ fontSize: '13px' }}>
          <StatusBadge severity="medium" label="SIMULATED" /> by <strong>{sim.simulated_by}</strong> at {formatUtc(sim.simulated_at)}
          {sim.reason && <> — “{sim.reason}”</>}
          <ul style={{ margin: '8px 0 0 18px' }}>
            {sim.actions.map((a) => <li key={a.id}>{a.id}: {a.action} <span style={muted}>— {a.outcome}</span></li>)}
          </ul>
          <div style={{ ...muted, marginTop: '6px' }}>{sim.note}</div>
        </div>
      )}
      {!sim && !state.canSimulate && <div style={muted}>{state.reason}</div>}
      {state.canSimulate && (
        <>
          <div style={muted}>Approved is not executed. A simulation rehearses the approved actions on record only; no command is run and no system is changed.</div>
          <input style={input} placeholder="Your name (required)" value={actor} onChange={(e) => setActor(e.target.value)} maxLength={100} />
          <div><ActionButton busy={busy} disabled={!actor.trim()} onClick={() => onSimulate(actor.trim())}>Run simulation (no real action)</ActionButton></div>
        </>
      )}
    </div>
  );
}

export function ReviewHistory({ history }) {
  if (!history || history.length === 0) return null;
  return (
    <div style={panel}>
      <div style={sectionTitle}>Earlier decisions (no longer current)</div>
      <div style={{ ...muted, marginBottom: '6px' }}>New correlated alerts changed the incident, so these decisions were voided and a new review is needed.</div>
      {history.map((h, i) => (
        <div key={i} style={{ fontSize: '13px', padding: '3px 0' }}>
          {h.review ? <><StatusBadge severity={h.review.decision.toLowerCase()} label={h.review.decision} /> by <strong>{h.review.reviewer}</strong> at {formatUtc(h.review.reviewed_at)}</> : 'Decision details unavailable'}
          {h.simulation && <> · simulated by {h.simulation.simulated_by}</>} · voided {formatUtc(h.superseded_at)}
        </div>
      ))}
    </div>
  );
}

function IncidentDetail({ id, onChanged }) {
  const { loading, error, data: inc, reload } = useAsync(() => api(`/incidents/${id}`), [id]);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  const act = async (fn) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await reload();
      onChanged();
    } catch (err) {
      setActionError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (loading && !inc) return <LoadingCard>Loading incident {id}...</LoadingCard>;
  if (error && !inc) return <ErrorCard title="Could not load incident" message={error} onRetry={reload} />;
  const details = inc.details || {};
  return (
    <div style={{ marginTop: '14px' }}>
      {actionError && <ErrorCard title="Action not completed" message={actionError} />}
      {(details.investigation_stale || details.recommendations_stale) && (
        <div style={{ ...panel, color: '#fde047', fontSize: '12px' }}>
          New correlated alerts changed this incident. {details.investigation_stale ? 'The investigation is out of date. ' : ''}{details.recommendations_stale ? 'The recommendations are out of date.' : ''}
        </div>
      )}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '14px', flexWrap: 'wrap' }}>
        <ActionButton variant="ghost" busy={busy} onClick={() => act(() => api(`/incidents/${id}/investigate`, { method: 'POST' }))}>Re-run investigation</ActionButton>
        <ActionButton variant="ghost" busy={busy} disabled={inc.human_approval_status !== 'PENDING'}
          title={inc.human_approval_status !== 'PENDING' ? 'A decision is recorded; recommendations are locked' : ''}
          onClick={() => act(() => api(`/incidents/${id}/recommend`, { method: 'POST' }))}>Generate recommendations</ActionButton>
      </div>
      <Correlation correlation={details.correlation} />
      <CorrelatedAlerts alerts={inc.alerts || []} />
      <Investigation inv={details.investigation} />
      <Recommendations recs={details.recommendations} response={details.response} />
      <Review incident={inc} busy={busy}
        onDecide={(decision, reviewer, reason) => act(() => api(`/incidents/${id}/${decision}`, { method: 'POST', body: { reviewer, reason: reason || null } }))} />
      <Simulation incident={inc} busy={busy}
        onSimulate={(actor) => act(() => api(`/incidents/${id}/simulate`, { method: 'POST', body: { reviewer: actor } }))} />
      <ReviewHistory history={details.review_history} />
    </div>
  );
}

export default function Incidents({ incidents, loading, error, refresh, refreshAlerts }) {
  const [openId, setOpenId] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [run, setRun] = useState(null);

  const runAction = async (fn) => {
    setBusy(true);
    setNotice(null);
    try {
      await fn();
    } catch (err) {
      setNotice({ error: true, text: err.message });
    } finally {
      setBusy(false);
      refresh();
      refreshAlerts();
    }
  };

  const correlate = () => runAction(async () => {
    const r = await api('/incidents/correlate', { method: 'POST' });
    setNotice({ text: `${r.message} Created ${r.created.length}, updated ${r.updated.length}, unchanged ${r.unchanged.length}.` });
  });
  const runPipeline = () => runAction(async () => {
    setRun(await api('/pipeline/run', { method: 'POST' }));
  });

  const visible = (incidents || []).filter((i) => i.status !== 'MERGED');
  const pending = visible.filter((i) => i.status === 'RESPONSE_PROPOSED' && i.human_approval_status === 'PENDING').length;

  return (
    <div>
      <div className="glass-card" style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        <div style={{ fontSize: '13px' }}>
          <strong>{visible.length}</strong> incident(s) · <strong>{pending}</strong> awaiting human review
          <div style={muted}>Incidents are built from alerts that share a host, IP or file hash within the time window. Actions are proposals only.</div>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <ActionButton busy={busy} onClick={runPipeline}><Play size={12} style={{ verticalAlign: '-2px' }} /> Run full pipeline</ActionButton>
          <ActionButton variant="ghost" busy={busy} onClick={correlate}><GitMerge size={12} style={{ verticalAlign: '-2px' }} /> Correlate only</ActionButton>
          <ActionButton variant="ghost" onClick={refresh}><RefreshCw size={12} style={{ verticalAlign: '-2px' }} /> Refresh</ActionButton>
        </div>
      </div>

      {notice && <ErrorCard title={notice.error ? 'Action failed' : 'Done'} message={notice.text} />}
      <PipelineRunReport run={run} />

      {loading && !incidents && <LoadingCard>Loading incidents...</LoadingCard>}
      {error && <ErrorCard title="Could not load incidents" message={error} onRetry={refresh} />}
      {!loading && !error && visible.length === 0 && (
        <EmptyCard title="No incidents yet">
          Run the full pipeline (or “Correlate only”) to group related alerts into incidents. At least two alerts must share a host, IP or file hash within the time window.
        </EmptyCard>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {visible.map((inc) => {
          const open = openId === inc.id;
          return (
            <div key={inc.id} className="glass-card" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px', marginBottom: '12px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px', flexWrap: 'wrap' }}>
                    <span className="code-font" style={{ fontSize: '14px', fontWeight: 700 }}>{inc.id}</span>
                    <StatusBadge severity={inc.severity} />
                    <span style={muted}>{inc.correlated_alert_ids.length} alerts correlated · {statusLabel(inc.status)}</span>
                  </div>
                  <h3 style={{ fontSize: '18px' }}>{inc.title}</h3>
                </div>
                <div style={{ padding: '4px 12px', borderRadius: '9999px', background: 'rgba(234, 179, 8, 0.1)', border: '1px solid rgba(234, 179, 8, 0.3)', color: '#fde047', fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}>
                  <UserCheck size={14} />
                  {inc.human_approval_status === 'PENDING' ? 'Awaiting analyst decision' : `Decision: ${inc.human_approval_status}${inc.status === 'RESPONSE_SIMULATED' ? ' · simulated' : ' · not executed'}`}
                </div>
              </div>

              {inc.ai_summary && (
                <div style={panel}>
                  <div style={sectionTitle}>Investigation summary</div>
                  <p style={{ fontSize: '13px' }}>{inc.ai_summary}</p>
                </div>
              )}
              {inc.recommended_action && (
                <div style={{ fontSize: '13px', marginBottom: '12px' }}>
                  <strong style={{ color: '#a78bfa' }}>Primary proposed action (requires approval):</strong> {inc.recommended_action}
                </div>
              )}
              <ActionButton variant="ghost" onClick={() => setOpenId(open ? null : inc.id)}>{open ? 'Hide details' : 'View timeline, evidence and recommendations'}</ActionButton>
              {open && <IncidentDetail id={inc.id} onChanged={() => { refresh(); refreshAlerts(); }} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
