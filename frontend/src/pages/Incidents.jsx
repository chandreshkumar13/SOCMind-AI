import React, { useState } from 'react';
import { UserCheck, RefreshCw, Play, GitMerge, Search, Filter } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import PipelineRunReport from '../components/PipelineRunReport';
import StaleNotice from '../components/StaleNotice';
import { ActionButton, EmptyCard, ErrorCard, LoadingCard } from '../components/StateCards';
import { api } from '../api';
import useAsync from '../lib/useAsync';
import { closedNotice, computedFindingsByAlert, formatUtc, groupFindings, loadMoreNote, recommendationView, reinvestigationNotice, reviewState, safeVirusTotalUrl, simulationState, statusLabel } from '../lib/view';
import {
  APPROVAL_FILTERS, DEFAULT_CRITERIA, SEVERITY_ORDER, SORT_OPTIONS, STATUS_FILTERS,
  filterAndSortIncidents, isDefaultView, shownSummary,
} from '../lib/incidentFilters';

const sectionTitle = { fontSize: '12px', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700, marginBottom: '8px' };
const panel = { background: 'rgba(0, 0, 0, 0.2)', padding: '12px 16px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', marginBottom: '14px' };
const muted = { fontSize: '12px', color: 'var(--text-muted)' };
const filterInput = { padding: '8px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px' };
const pill = (active) => ({ padding: '6px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: active ? 'var(--accent-cyan)' : 'transparent', color: active ? '#090d16' : 'var(--text-muted)', fontSize: '11px', fontWeight: 700, cursor: 'pointer' });

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

// Computed findings: rules applied to each alert's own fields by triage. Shown apart from verified facts and threat intelligence.
export function ComputedFindings({ alerts }) {
  const rows = computedFindingsByAlert(alerts);
  if (rows.length === 0) return null;
  return (
    <div style={{ ...panel, borderColor: 'rgba(148, 163, 184, 0.4)' }}>
      <div style={sectionTitle}>Computed findings ({rows.reduce((n, r) => n + r.statements.length, 0)})</div>
      <div style={{ ...muted, marginBottom: '6px' }}>
        Deterministic rules applied to each alert's own fields. They are not threat intelligence and not verified facts.
      </div>
      {rows.map((row) => (
        <div key={row.id} style={{ fontSize: '13px', padding: '4px 0' }}>
          <span className="code-font">{row.id}</span> <span style={muted}>{row.title}</span>
          <ul style={{ margin: '4px 0 0 18px' }}>
            {row.statements.map((st, i) => <li key={i}>{st}</li>)}
          </ul>
        </div>
      ))}
    </div>
  );
}

// Closed alerts: a fully closed incident is read-only, and a partly closed one says which alerts left it.
export function ClosedNotice({ incident }) {
  const notice = closedNotice(incident);
  if (!notice) return null;
  const closedStyle = { ...panel, borderColor: 'rgba(148, 163, 184, 0.5)' };
  return (
    <div style={closedStyle}>
      <div style={sectionTitle}>{notice.level === 'closed' ? 'Closed incident' : 'Closed alerts removed from this incident'}</div>
      <div style={{ fontSize: '13px' }}>{notice.text}</div>
      {notice.alertIds.length > 0 && (
        <div style={{ ...muted, marginTop: '6px' }}>Closed alerts: <span className="code-font">{notice.alertIds.join(', ')}</span></div>
      )}
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

      {groups.external_intel.length > 0 && (
        <div style={{ ...panel, borderColor: 'rgba(79, 172, 254, 0.45)' }}>
          <div style={{ ...sectionTitle, color: '#4facfe' }}>VirusTotal intelligence — not independently verified ({groups.external_intel.length})</div>
          <div style={{ ...muted, marginBottom: '6px' }}>Third-party engine verdicts reported by VirusTotal. They can include false positives and are not confirmed by SOCMind AI.</div>
          {groups.external_intel.map((f, i) => (
            <div key={i} style={{ fontSize: '13px', padding: '3px 0' }}>
              • {f.statement}
              {safeVirusTotalUrl(f.reference_url) && (
                <> <a href={safeVirusTotalUrl(f.reference_url)} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-cyan)' }}>VirusTotal report</a></>
              )}
            </div>
          ))}
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

// Recommendations whose decision was withdrawn: kept as history, never shown as current proposals.
function SupersededRecommendations({ view }) {
  const recs = view.recommendations;
  const when = view.supersededAt ? ` ${formatUtc(view.supersededAt)}` : '';
  return (
    <div style={{ ...panel, borderColor: 'rgba(148, 163, 184, 0.4)' }}>
      <div style={{ ...sectionTitle, color: 'var(--text-muted)' }}>Superseded recommendations, not current ({recs.length})</div>
      <div style={{ ...muted, marginBottom: '10px' }}>
        These are the proposals an earlier decision was based on. That decision was withdrawn{when}: {view.reason}.
        They are kept for the record only. Nothing was executed.
      </div>
      {recs.map((r) => (
        <div key={r.id} style={{ padding: '8px 12px', marginBottom: '8px', borderRadius: 'var(--radius-sm)', border: '1px dashed var(--border-color)', opacity: 0.75 }}>
          <div style={{ fontWeight: 600, fontSize: '13px' }}>{r.id} · {r.action}</div>
          <div style={{ marginTop: '4px' }}><StatusBadge severity="low" label="SUPERSEDED" /></div>
        </div>
      ))}
    </div>
  );
}

// Takes the whole incident details: whether a decision is in force decides if the recommendations are current or history.
export function Recommendations({ details }) {
  const view = recommendationView(details);
  const recs = view.recommendations;
  const response = (details && details.response) || null;
  if (view.kind === 'none') return <div style={{ ...panel, ...muted }}>No recommendations yet.</div>;
  if (view.kind === 'superseded') return <SupersededRecommendations view={view} />;
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
      <div style={sectionTitle}>Earlier decisions (historical, no longer current)</div>
      <div style={{ ...muted, marginBottom: '6px' }}>
        Withdrawn decisions, kept with the recommendations they were based on. None of them applies to the current analysis.
      </div>
      {history.map((h, i) => (
        <div key={i} style={{ fontSize: '13px', padding: '6px 0', borderBottom: '1px solid var(--border-color)' }}>
          {h.review ? <><StatusBadge severity={h.review.decision.toLowerCase()} label={h.review.decision} /> by <strong>{h.review.reviewer}</strong> at {formatUtc(h.review.reviewed_at)}</> : 'Decision details unavailable'}
          {h.simulation && <> · simulated by {h.simulation.simulated_by}</>}
          <div style={muted}>Withdrawn {formatUtc(h.superseded_at)}{h.superseded_by ? `: ${h.superseded_by}` : ''}</div>
          {(h.recommendations || []).length > 0 && (
            <div style={muted}>
              Recommendations at the time ({h.recommendations.length}): {h.recommendations.map((r) => `${r.action} [${r.status}${r.simulation_status === 'SIMULATED' ? ', simulated' : ''}]`).join('; ')}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// Asks before re-investigating an incident that has a recorded decision. Renders nothing when nothing would be withdrawn.
export function ReinvestigateConfirm({ notice, busy, onConfirm, onCancel }) {
  if (!notice) return null;
  return (
    <div style={{ ...panel, borderColor: 'rgba(234, 179, 8, 0.5)', display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div style={{ ...sectionTitle, color: '#fde047' }}>Withdraw the recorded decision?</div>
      <div style={{ fontSize: '13px' }}>{notice}</div>
      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
        <ActionButton variant="danger" busy={busy} onClick={onConfirm}>Withdraw decision and re-investigate</ActionButton>
        <ActionButton variant="ghost" disabled={busy} onClick={onCancel}>Cancel</ActionButton>
      </div>
    </div>
  );
}

function IncidentDetail({ id, onChanged }) {
  const { loading, error, data: inc, reload } = useAsync(() => api(`/incidents/${id}`), [id]);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [confirming, setConfirming] = useState(false);   // the re-investigation warning is open

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

  const reinvestigate = () => act(() => api(`/incidents/${id}/investigate`, { method: 'POST' }));

  if (loading && !inc) return <LoadingCard>Loading incident {id}...</LoadingCard>;
  if (error && !inc) return <ErrorCard title="Could not load incident" message={error} onRetry={reload} />;
  const details = inc.details || {};
  const closed = inc.status === 'CLOSED';
  return (
    <div style={{ marginTop: '14px' }}>
      {actionError && <ErrorCard title="Action not completed" message={actionError} />}
      <ClosedNotice incident={inc} />
      <StaleNotice details={details} />
      <div style={{ display: 'flex', gap: '10px', marginBottom: '14px', flexWrap: 'wrap' }}>
        <ActionButton variant="ghost" busy={busy} disabled={closed} title={closed ? 'This incident is closed' : (reinvestigationNotice(inc) || '')}
          onClick={() => (reinvestigationNotice(inc) ? setConfirming(true) : reinvestigate())}>Re-run investigation</ActionButton>
        <ActionButton variant="ghost" busy={busy} disabled={closed || inc.human_approval_status !== 'PENDING'}
          title={closed ? 'This incident is closed' : (inc.human_approval_status !== 'PENDING' ? 'A decision is recorded; recommendations are locked' : '')}
          onClick={() => act(() => api(`/incidents/${id}/recommend`, { method: 'POST' }))}>Generate recommendations</ActionButton>
      </div>
      <ReinvestigateConfirm notice={confirming ? reinvestigationNotice(inc) : null} busy={busy}
        onConfirm={() => { setConfirming(false); reinvestigate(); }} onCancel={() => setConfirming(false)} />
      <Correlation correlation={details.correlation} />
      <CorrelatedAlerts alerts={inc.alerts || []} />
      <ComputedFindings alerts={inc.alerts || []} />
      <Investigation inv={details.investigation} />
      <Recommendations details={details} />
      <Review incident={inc} busy={busy}
        onDecide={(decision, reviewer, reason) => act(() => api(`/incidents/${id}/${decision}`, { method: 'POST', body: { reviewer, reason: reason || null } }))} />
      <Simulation incident={inc} busy={busy}
        onSimulate={(actor) => act(() => api(`/incidents/${id}/simulate`, { method: 'POST', body: { reviewer: actor } }))} />
      <ReviewHistory history={details.review_history} />
    </div>
  );
}

export default function Incidents({ incidents, loading, error, refresh, refreshAlerts, incidentsTotal, loadMoreIncidents, loadingMore }) {
  const [openId, setOpenId] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [run, setRun] = useState(null);
  const [criteria, setCriteria] = useState(DEFAULT_CRITERIA);   // search, filters and sort; kept across refreshes

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
  const shown = filterAndSortIncidents(incidents, criteria);
  const updateCriteria = (patch) => setCriteria((current) => ({ ...current, ...patch }));
  const clearFilters = () => setCriteria(DEFAULT_CRITERIA);

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

      {loadMoreNote(visible.length, incidentsTotal, 'incidents') && (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap', fontSize: '12px', color: '#fde047', marginBottom: '12px' }}>
          <span>{loadMoreNote(visible.length, incidentsTotal, 'incidents')} The filters and sort below apply to the loaded incidents.</span>
          {loadMoreIncidents && (
            <button onClick={loadMoreIncidents} disabled={loadingMore} style={{ padding: '4px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.05)', color: 'var(--accent-cyan)', fontSize: '12px', cursor: loadingMore ? 'wait' : 'pointer' }}>
              {loadingMore ? 'Loading...' : 'Load more'}
            </button>
          )}
        </div>
      )}

      {visible.length > 0 && (
        <div className="glass-card" style={{ marginBottom: '12px', display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: '240px', maxWidth: '420px' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              aria-label="Search incidents"
              placeholder="Search id, title, summary, host, user or IP..."
              value={criteria.search}
              onChange={(e) => updateCriteria({ search: e.target.value })}
              style={{ ...filterInput, width: '100%', paddingLeft: '36px' }}
            />
          </div>
          <div role="group" aria-label="Filter by severity" style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
            <Filter size={16} color="var(--text-muted)" />
            {['ALL', ...SEVERITY_ORDER].map((sev) => (
              <button
                key={sev}
                type="button"
                aria-pressed={criteria.severity === sev}
                onClick={() => updateCriteria({ severity: sev })}
                style={pill(criteria.severity === sev)}
              >
                {sev}
              </button>
            ))}
          </div>
          <select aria-label="Filter by approval" value={criteria.approval} onChange={(e) => updateCriteria({ approval: e.target.value })} style={filterInput}>
            {APPROVAL_FILTERS.map((v) => <option key={v} value={v}>{v === 'ALL' ? 'Any approval' : `Approval: ${v.toLowerCase()}`}</option>)}
          </select>
          <select aria-label="Filter by workflow status" value={criteria.status} onChange={(e) => updateCriteria({ status: e.target.value })} style={filterInput}>
            {STATUS_FILTERS.map((v) => <option key={v} value={v}>{v === 'ALL' ? 'Any status' : statusLabel(v)}</option>)}
          </select>
          <select aria-label="Sort incidents" value={criteria.sort} onChange={(e) => updateCriteria({ sort: e.target.value })} style={filterInput}>
            {SORT_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          {!isDefaultView(criteria) && <ActionButton variant="ghost" onClick={clearFilters}>Clear filters</ActionButton>}
        </div>
      )}
      {visible.length > 0 && <div style={{ ...muted, marginBottom: '12px' }}>{shownSummary(shown.length, visible.length)}</div>}

      {notice && <ErrorCard title={notice.error ? 'Action failed' : 'Done'} message={notice.text} />}
      <PipelineRunReport run={run} />

      {loading && !incidents && <LoadingCard>Loading incidents...</LoadingCard>}
      {error && <ErrorCard title="Could not load incidents" message={error} onRetry={refresh} />}
      {!loading && !error && visible.length === 0 && (
        <EmptyCard title="No incidents yet">
          Run the full pipeline (or “Correlate only”) to group related alerts into incidents. At least two alerts must share a host, IP or file hash within the time window.
        </EmptyCard>
      )}

      {!loading && !error && visible.length > 0 && shown.length === 0 && (
        <EmptyCard title="No incidents match the current filters">
          Try a different search term or change the filters. <ActionButton variant="ghost" onClick={clearFilters}>Clear filters</ActionButton>
        </EmptyCard>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {shown.map((inc) => {
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
