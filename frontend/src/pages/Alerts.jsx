import React, { useEffect, useRef, useState } from 'react';
import { Filter, Search, PlusCircle, RefreshCw, AlertTriangle } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import { ActionButton, ErrorCard } from '../components/StateCards';
import { api } from '../api';
import { alertSearchPath, detectionLabel, enrichmentNotices, fetchAlertSearch, formatUtc, intelSource, isRetryableLookup, loadMoreNote, lookupStatusLabel, refreshedSelection, reputationKey, reputationSource, safeVirusTotalUrl, searchCapNote } from '../lib/view';
import { CLOSE_CONFIRMATION, SEVERITY_FILTERS, STATUS_FILTERS, alertMatchesSearch, filterAlerts, isAlertClosed, statusFilterLabel } from '../lib/alertFilters';

// Where the reputations came from, as stored on the record. Live results are blue and name their provider;
// everything else keeps the amber "unverified" tint.
function SourceTag({ source }) {
  const colours = source.live
    ? { color: '#4facfe', border: '1px solid #4facfe' }
    : source.kind === 'mock'
      ? { color: '#fde047', border: '1px solid rgba(234, 179, 8, 0.6)' }
      : { color: 'var(--text-muted)', border: '1px solid var(--border-color)' };
  return (
    <span style={{ ...colours, fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '9999px' }}>
      {source.label}
    </span>
  );
}

// Triage and enrichment results stored on the alert (normalized_data.triage / .enrichment)
export function AnalysisPanels({ alert, busy, onRun, runError }) {
  const data = alert.normalized_data || {};
  const triage = data.triage;
  const enr = data.enrichment;
  const closed = alert.status === 'CLOSED';
  const small = { fontSize: '11px', color: 'var(--text-muted)' };
  const source = intelSource(enr);
  const btn = { padding: '4px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.05)', color: 'var(--accent-cyan)', fontSize: '12px', cursor: busy ? 'wait' : 'pointer' };
  return (
    <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
        <button style={btn} disabled={busy} onClick={() => onRun('triage')}>{triage ? 'Re-run triage' : 'Run triage'}</button>
        <button style={btn} disabled={busy} onClick={() => onRun('enrich')}>{enr ? 'Re-run enrichment' : 'Run enrichment'}</button>
        {closed && <span style={small}>Closed alerts keep their CLOSED status.</span>}
      </div>
      {runError && <div style={{ fontSize: '12px', color: '#f87171' }}>{runError}</div>}

      <div>
        <strong style={{ color: 'var(--accent-cyan)' }}>Triage</strong>
        {!triage && <div style={small}>Not triaged yet.</div>}
        {triage && (
          <div style={{ fontSize: '12px', marginTop: '4px' }}>
            Score <strong>{triage.suspicion_score}/100</strong> · priority <StatusBadge severity={triage.priority} />
            <div style={{ ...small, marginTop: '4px' }}>Computed findings: rules applied to this alert's own fields, not threat intelligence.</div>
            <ul style={{ margin: '6px 0 0 16px' }}>
              {(triage.indicators || []).map((i, k) => <li key={k}>{i}</li>)}
              {(triage.indicators || []).length === 0 && <li style={small}>No additional risk indicators.</li>}
            </ul>
          </div>
        )}
      </div>

      <div>
        <strong style={{ color: 'var(--accent-cyan)' }}>IOC enrichment</strong>
        {!enr && <div style={small}>Not enriched yet.</div>}
        {enr && (
          <div style={{ fontSize: '12px', marginTop: '4px' }}>
            {enr.total_iocs_extracted} IOC(s): {enr.summary.malicious} malicious · {enr.summary.suspicious} suspicious · {enr.summary.clean} clean · {enr.summary.unknown} unknown
            {enr.timestamp && <div style={{ ...small, marginTop: '4px' }}>Recorded {formatUtc(enr.timestamp)}</div>}
            {source && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginTop: '6px' }}>
                <SourceTag source={source} />
                <span style={small}>
                  {source.live ? 'third-party verdicts · not independently verified' : source.kind === 'mock' ? 'offline sample data · not verified' : ''}
                </span>
              </div>
            )}
            {source && <div style={{ ...small, color: '#fde047', marginTop: '4px' }}>{source.disclaimer}</div>}
            {enrichmentNotices(enr).map((note, k) => <div key={k} style={{ ...small, color: '#fb923c', marginTop: '4px' }}>{note}</div>)}
            {(enr.encoded_payloads || []).map((p, k) => (
              <div key={k} style={{ marginTop: '8px', padding: '8px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600 }}>
                  Encoded command ({p.kind === 'from_base64_string' ? 'FromBase64String' : 'PowerShell -EncodedCommand'}): {p.status === 'decoded' ? `decoded ${p.encoding}` : p.reason}
                </div>
                <div style={{ ...small, color: '#fde047', marginTop: '2px' }}>{p.provenance}</div>
                {p.status === 'decoded' && (
                  <pre style={{ ...small, whiteSpace: 'pre-wrap', wordBreak: 'break-all', marginTop: '4px', color: 'var(--text-main)' }}>
                    {p.decoded_text}{p.truncated ? ' …(truncated)' : ''}
                  </pre>
                )}
              </div>
            ))}
            {enr.iocs.length > 0 && (
              <table className="cyber-table" style={{ marginTop: '6px' }}>
                <thead>
                  <tr>
                    <th>Type</th><th>Value</th><th>Reputation ({reputationSource(enr)})</th>
                    {source && source.live && <th>Lookup</th>}
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {enr.iocs.map((i, k) => (
                    <tr key={k}>
                      <td className="code-font">{i.type}</td>
                      <td className="code-font" style={{ wordBreak: 'break-all', fontSize: '10px' }}>{i.value}</td>
                      <td><StatusBadge severity={reputationKey(i.reputation)} label={i.reputation} /></td>
                      {source && source.live && (
                        <td style={{ ...small, color: isRetryableLookup(i.lookup_status) ? '#fb923c' : 'var(--text-muted)' }}>
                          {lookupStatusLabel(i.lookup_status)}
                          {detectionLabel(i.detections) && <div>{detectionLabel(i.detections)}</div>}
                          {i.cached && <div>from cache</div>}
                          {safeVirusTotalUrl(i.reference_url) && (
                            <a href={safeVirusTotalUrl(i.reference_url)} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-cyan)' }}>VirusTotal report</a>
                          )}
                        </td>
                      )}
                      <td style={small}>{i.evidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
      {data.incident_id && <div style={small}>Part of incident <strong className="code-font">{data.incident_id}</strong> (see Correlated Incidents).</div>}
    </div>
  );
}

// Status management for one alert: the Close alert button, its confirmation and any error. Closing marks the alert CLOSED (it is
// never deleted), removes it from active incidents, and cannot be undone. Nothing is executed. The request is sent only after the
// user confirms.
export function CloseAlertControl({ alert, confirming, busy, error, onAsk, onCancel, onConfirm }) {
  const closed = isAlertClosed(alert);
  const small = { fontSize: '11px', color: 'var(--text-muted)' };
  return (
    <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border-color)' }}>
      <strong style={{ color: 'var(--accent-cyan)' }}>Status management</strong>
      {closed && <div style={{ ...small, marginTop: '4px' }}>This alert is CLOSED. A closed alert cannot be reopened.</div>}
      {!confirming && (
        <div style={{ marginTop: '8px' }}>
          <ActionButton variant="danger" disabled={closed || busy} title={closed ? 'This alert is already closed' : 'Mark this alert as CLOSED'} onClick={onAsk}>
            Close alert
          </ActionButton>
        </div>
      )}
      {confirming && !closed && (
        <div role="alertdialog" aria-label="Confirm closing the alert" style={{ marginTop: '8px', padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(239, 68, 68, 0.5)' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-main)', marginBottom: '8px' }}>{CLOSE_CONFIRMATION}</div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <ActionButton variant="danger" busy={busy} onClick={onConfirm}>Confirm close</ActionButton>
            <ActionButton variant="ghost" disabled={busy} onClick={onCancel}>Cancel</ActionButton>
          </div>
        </div>
      )}
      {error && <div style={{ marginTop: '10px' }}><ErrorCard title="Could not close the alert" message={error} /></div>}
    </div>
  );
}

// The search and filter rules live in lib/alertFilters.js (pure, unit-tested). alertMatchesSearch is still exported from this page,
// because the integration test imports it from here.
export { alertMatchesSearch };

// Pause after the last keystroke before asking the server, so typing does not send a request per character.
const SEARCH_DEBOUNCE_MS = 250;

export default function Alerts({ alerts, loading, error, refreshAlerts, seedSampleAlerts, totalAlerts, alertsTotal, loadMoreAlerts, loadingMore }) {
  const [analysisBusy, setAnalysisBusy] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [fetchingDetail, setFetchingDetail] = useState(false);
  const [ingesting, setIngesting] = useState(false);
  const [searchResult, setSearchResult] = useState(null);   // { term, rows } from GET /alerts?search=
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);
  const [ingestError, setIngestError] = useState(null);     // shown inline instead of a blocking alert()
  const [closeConfirming, setCloseConfirming] = useState(false);   // the "close this alert?" question is showing
  const [closing, setClosing] = useState(false);
  const [closeError, setCloseError] = useState(null);
  const searchSequence = useRef(0);   // a response from an older search run is ignored

  // The drawer holds its own copy of the alert. Keep it in step with the list the page loads, so a result stored
  // elsewhere (another tool, the pipeline, a re-run) replaces the older snapshot instead of being hidden by it.
  useEffect(() => {
    setSelectedAlert(prev => (prev ? refreshedSelection(prev, alerts) : prev));
  }, [alerts]);

  // A different alert starts without a pending close question or an old error.
  useEffect(() => {
    setCloseConfirming(false);
    setCloseError(null);
  }, [selectedAlert?.id]);

  // Server-side search over every alert, not only the loaded first page. It waits briefly after typing, and it runs
  // again whenever the list reloads (ingest, triage, enrichment, refresh), so matches never show an older state.
  useEffect(() => {
    const sequence = ++searchSequence.current;
    const path = alertSearchPath(searchQuery);
    setSearchError(null);
    if (!path) {
      setSearchResult(null);
      setSearching(false);
      return undefined;
    }
    setSearching(true);
    const timer = setTimeout(async () => {
      const next = await fetchAlertSearch(searchQuery, api);
      if (sequence !== searchSequence.current) return;   // a newer search has started, or the page has unmounted
      setSearchResult(next.result);   // null after a failure, so the page falls back to the loaded alerts
      setSearchError(next.error);
      setSearching(false);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchQuery, alerts]);

  useEffect(() => () => { searchSequence.current += 1; }, []);

  // Client-side severity and status filters (see lib/alertFilters.js). While a search is active, the server's matches replace the loaded list. Until they
  // arrive, or if the search fails, the loaded list is filtered locally so the table never goes blank.
  const searchActive = alertSearchPath(searchQuery) !== null;
  const serverMatches = searchActive && searchResult && searchResult.term === searchQuery.trim() ? searchResult.rows : null;
  const capNote = serverMatches ? searchCapNote(serverMatches.length) : '';
  const filteredAlerts = filterAlerts(alerts, { severity: filterSeverity, status: filterStatus, search: searchQuery }, serverMatches);

  // Handle clicking row to inspect single alert details via GET /api/v1/alerts/{id}
  const handleInspectAlert = async (alertId) => {
    setFetchingDetail(true);
    try {
      setSelectedAlert(await api(`/alerts/${alertId}`));
    } catch (err) {
      console.error(err);
      const fallback = alerts.find(a => a.id === alertId);
      setSelectedAlert(fallback);
    } finally {
      setFetchingDetail(false);
    }
  };

  // Handle Ingesting Synthetic Test Alert via POST /api/v1/alerts
  const handleIngestTestAlert = async () => {
    setIngesting(true);
    setIngestError(null);
    const syntheticPayload = {
      alert_title: "Synthetic Test Ingestion: Unrecognized Admin CLI Script Execution",
      source: "CrowdStrike EDR",
      raw_severity: "High",
      host: `WORKSTATION-TEST-${Math.floor(Math.random() * 90 + 10)}`,
      username: "admin_test",
      source_ip: "192.168.100.45",
      destination_ip: "198.51.100.99",
      command_line: "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Write-Host 'Synthetic Test Alert Ingested'",
      description: "User triggered synthetic test alert ingestion from SOCMind AI Analyst Console."
    };

    try {
      await api('/alerts', { method: 'POST', body: syntheticPayload });
      await refreshAlerts();
    } catch (err) {
      setIngestError(`Error ingesting test alert: ${err.message}`);
    } finally {
      setIngesting(false);
    }
  };

  // Run triage or enrichment on the selected alert; the response carries the updated alert
  const handleRunAnalysis = async (kind) => {
    setAnalysisBusy(true);
    setAnalysisError(null);
    try {
      const res = await api(`/alerts/${selectedAlert.id}/${kind}`, { method: 'POST' });
      setSelectedAlert(res.alert);
      await refreshAlerts();
    } catch (err) {
      setAnalysisError(err.message);
    } finally {
      setAnalysisBusy(false);
    }
  };

  // Close the selected alert via DELETE /api/v1/alerts/{id}. It is reached only from the confirmation, never from the first click.
  // On success the alert shows as CLOSED at once, and alerts, incidents and statistics are reloaded.
  const handleConfirmClose = async () => {
    const id = selectedAlert.id;
    setClosing(true);
    setCloseError(null);
    try {
      await api(`/alerts/${id}`, { method: 'DELETE' });
      setCloseConfirming(false);
      setSelectedAlert((prev) => (prev && prev.id === id ? { ...prev, status: 'CLOSED' } : prev));
      await refreshAlerts();
    } catch (err) {
      setCloseError(err.message);
    } finally {
      setClosing(false);
    }
  };

  return (
    <div>
      {/* Top Filter and Actions Bar */}
      <div className="glass-card" style={{ marginBottom: '20px', display: 'flex', gap: '16px', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: '12px', flex: 1, minWidth: '300px' }}>
          <div style={{ position: 'relative', flex: 1, maxWidth: '380px' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input 
              type="text" 
              placeholder="Search title, host, user, IP, or source..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px 8px 36px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-color)',
                background: 'var(--bg-dark)',
                color: 'var(--text-main)',
                fontSize: '13px',
                outline: 'none'
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
            <Filter size={16} color="var(--text-muted)" />
            {SEVERITY_FILTERS.map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                style={{
                  padding: '6px 10px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-color)',
                  background: filterSeverity === sev ? 'var(--accent-cyan)' : 'transparent',
                  color: filterSeverity === sev ? '#090d16' : 'var(--text-muted)',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          <select aria-label="Filter by alert status" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '12px' }}>
            {STATUS_FILTERS.map((s) => <option key={s} value={s}>{statusFilterLabel(s)}</option>)}
          </select>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button 
            onClick={handleIngestTestAlert}
            disabled={ingesting}
            style={{
              padding: '8px 14px',
              borderRadius: 'var(--radius-sm)',
              border: 'none',
              background: 'linear-gradient(135deg, #00f2fe, #4facfe)',
              color: '#090d16',
              fontWeight: 700,
              fontSize: '12px',
              cursor: ingesting ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <PlusCircle size={15} />
            {ingesting ? 'Ingesting...' : 'Ingest Test Alert'}
          </button>

          <button 
            onClick={refreshAlerts}
            style={{
              padding: '8px 12px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-color)',
              background: 'transparent',
              color: 'var(--text-muted)',
              fontSize: '12px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <RefreshCw size={14} className={loading ? 'pulse' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {ingestError && (
        <div role="alert" style={{ fontSize: '12px', color: '#f87171', marginBottom: '10px' }}>{ingestError}</div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="glass-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--accent-cyan)' }}>
            Fetching Normalized Alerts from Database...
          </div>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="glass-card" style={{ padding: '24px', borderLeft: '4px solid #ef4444', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#ef4444', fontWeight: 700, fontSize: '15px' }}>
            <AlertTriangle size={20} />
            Backend Connection Notice
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '6px' }}>
            {error}. Check that the backend server is running and reachable from this page.
          </p>
          <button 
            onClick={refreshAlerts} 
            style={{ marginTop: '12px', padding: '6px 14px', borderRadius: 'var(--radius-sm)', border: 'none', background: '#ef4444', color: '#fff', fontSize: '12px', fontWeight: 700, cursor: 'pointer' }}
          >
            Retry Connection
          </button>
        </div>
      )}

      {!loading && !searchActive && loadMoreNote(alerts.length, alertsTotal, 'alerts') && (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap', fontSize: '12px', color: '#fde047', marginBottom: '10px' }}>
          <span>{loadMoreNote(alerts.length, alertsTotal, 'alerts')} The severity and status filters apply to the loaded alerts; search covers every alert.</span>
          {loadMoreAlerts && (
            <button onClick={loadMoreAlerts} disabled={loadingMore} style={{ padding: '4px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.05)', color: 'var(--accent-cyan)', fontSize: '12px', cursor: loadingMore ? 'wait' : 'pointer' }}>
              {loadingMore ? 'Loading...' : 'Load more'}
            </button>
          )}
        </div>
      )}

      {!loading && searchActive && (searchError || searching || capNote) && (
        <div style={{ fontSize: '12px', color: searchError ? '#f87171' : '#fde047', marginBottom: '10px' }}>
          {searchError
            ? `Search failed: ${searchError}. Showing matches from the loaded alerts only.`
            : searching ? 'Searching all alerts...' : capNote}
        </div>
      )}

      {/* Main Alert Table & Details View */}
      {!loading && (
        <div style={{ display: 'grid', gridTemplateColumns: selectedAlert ? '1.5fr 1fr' : '1fr', gap: '20px' }}>
          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Alert Title</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Host / User</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                      {alerts.length === 0 ? (
                        <>
                          No alerts have been ingested yet.{' '}
                          {seedSampleAlerts && (
                            <button onClick={seedSampleAlerts} style={{ marginLeft: '8px', padding: '4px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.05)', color: 'var(--accent-cyan)', fontSize: '12px', cursor: 'pointer' }}>
                              Load sample (synthetic) alerts
                            </button>
                          )}
                        </>
                      ) : 'No security alerts found matching the active search/severity/status filter.'}
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map(a => (
                    <tr 
                      key={a.id} 
                      style={{ background: selectedAlert?.id === a.id ? 'var(--bg-card-hover)' : 'transparent' }}
                    >
                      <td className="code-font">{a.id}</td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {formatUtc(a.timestamp)}
                      </td>
                      <td style={{ fontWeight: 600 }}>{a.alert_title || a.alert_name}</td>
                      <td style={{ fontSize: '12px' }}>{a.source || a.source_system}</td>
                      <td><StatusBadge severity={a.severity || a.raw_severity} /></td>
                      <td className="code-font">{a.host || a.host_name || 'N/A'} ({a.username || a.user || 'N/A'})</td>
                      <td><span className="badge badge-low">{a.status || 'NEW'}</span></td>
                      <td>
                        <button 
                          onClick={() => handleInspectAlert(a.id)}
                          style={{
                            padding: '4px 10px',
                            borderRadius: 'var(--radius-sm)',
                            border: '1px solid var(--border-color)',
                            background: 'rgba(255, 255, 255, 0.05)',
                            color: 'var(--accent-cyan)',
                            fontSize: '12px',
                            cursor: 'pointer'
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Alert Detail Drawer (GET /api/v1/alerts/{id}) */}
          {selectedAlert && (
            <div className="glass-card" style={{ position: 'sticky', top: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '16px' }}>
                  Alert Detail: <span className="code-font">{selectedAlert.id}</span>
                </h3>
                <button 
                  onClick={() => setSelectedAlert(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '16px' }}
                >
                  ✕
                </button>
              </div>

              {fetchingDetail ? (
                <div style={{ fontSize: '12px', color: 'var(--accent-cyan)' }}>Fetching normalized record from DB...</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div>
                    <strong style={{ color: 'var(--text-muted)' }}>Alert Title:</strong>
                    <div style={{ fontWeight: 600, color: '#fff' }}>{selectedAlert.alert_title || selectedAlert.alert_name}</div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <div>
                      <strong style={{ color: 'var(--text-muted)' }}>Source System:</strong>
                      <div>{selectedAlert.source || selectedAlert.source_system}</div>
                    </div>
                    <div>
                      <strong style={{ color: 'var(--text-muted)' }}>Severity:</strong>
                      <div><StatusBadge severity={selectedAlert.severity || selectedAlert.raw_severity} /></div>
                    </div>
                  </div>

                  <div>
                    <strong style={{ color: 'var(--text-muted)' }}>Description:</strong>
                    <div style={{ fontSize: '12px', color: 'var(--text-main)', marginTop: '2px' }}>
                      {selectedAlert.description}
                    </div>
                  </div>

                  <div>
                    <strong style={{ color: 'var(--text-muted)' }}>Command Line Payload (DATA ONLY):</strong>
                    <pre style={{ 
                      background: 'var(--bg-dark)', 
                      padding: '10px', 
                      borderRadius: 'var(--radius-sm)', 
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--accent-cyan)',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      marginTop: '4px'
                    }}>
                      {selectedAlert.command_line || 'None'}
                    </pre>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <div>
                      <strong style={{ color: 'var(--text-muted)' }}>Source / Host:</strong>
                      <div className="code-font">{selectedAlert.host || selectedAlert.host_name || 'N/A'} ({selectedAlert.username || selectedAlert.user || 'N/A'})</div>
                    </div>
                    <div>
                      <strong style={{ color: 'var(--text-muted)' }}>Source IP:</strong>
                      <div className="code-font">{selectedAlert.source_ip || selectedAlert.ip_address || 'N/A'}</div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <div>
                      <strong style={{ color: 'var(--text-muted)' }}>Destination IP:</strong>
                      <div className="code-font">{selectedAlert.destination_ip || 'N/A'}</div>
                    </div>
                    <div>
                      <strong style={{ color: 'var(--text-muted)' }}>File Hash:</strong>
                      <div className="code-font" style={{ fontSize: '10px' }}>
                        {selectedAlert.file_hash ? selectedAlert.file_hash.substring(0, 16) + '...' : 'N/A'}
                      </div>
                    </div>
                  </div>

                  <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border-color)' }}>
                    <strong style={{ color: 'var(--accent-cyan)' }}>Database Metadata:</strong>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Status: <strong>{selectedAlert.status || 'NEW'}</strong> | Ext ID: <code>{selectedAlert.external_alert_id || selectedAlert.id}</code>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px', display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                      Record updated {formatUtc(selectedAlert.updated_at)}
                      <button
                        onClick={() => handleInspectAlert(selectedAlert.id)}
                        disabled={fetchingDetail}
                        style={{ padding: '2px 8px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'transparent', color: 'var(--accent-cyan)', fontSize: '11px', cursor: fetchingDetail ? 'wait' : 'pointer' }}
                      >
                        Reload from server
                      </button>
                    </div>
                  </div>

                  <AnalysisPanels alert={selectedAlert} busy={analysisBusy} onRun={handleRunAnalysis} runError={analysisError} />
                  <CloseAlertControl alert={selectedAlert} confirming={closeConfirming} busy={closing} error={closeError}
                    onAsk={() => { setCloseError(null); setCloseConfirming(true); }}
                    onCancel={() => { setCloseConfirming(false); setCloseError(null); }}
                    onConfirm={handleConfirmClose} />
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
