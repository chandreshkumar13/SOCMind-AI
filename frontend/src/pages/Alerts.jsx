import React, { useState } from 'react';
import { Filter, Search, PlusCircle, RefreshCw, AlertTriangle } from 'lucide-react';
import StatusBadge from '../components/StatusBadge';
import { api } from '../api';
import { reputationKey } from '../lib/view';

// Triage and enrichment results stored on the alert (normalized_data.triage / .enrichment)
export function AnalysisPanels({ alert, busy, onRun, runError }) {
  const data = alert.normalized_data || {};
  const triage = data.triage;
  const enr = data.enrichment;
  const closed = alert.status === 'CLOSED';
  const small = { fontSize: '11px', color: 'var(--text-muted)' };
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
            {enr.disclaimer && <div style={{ ...small, color: '#fde047', marginTop: '4px' }}>{enr.disclaimer}</div>}
            {enr.iocs.length > 0 && (
              <table className="cyber-table" style={{ marginTop: '6px' }}>
                <thead><tr><th>Type</th><th>Value</th><th>Reputation (mock)</th><th>Evidence</th></tr></thead>
                <tbody>
                  {enr.iocs.map((i, k) => (
                    <tr key={k}>
                      <td className="code-font">{i.type}</td>
                      <td className="code-font" style={{ wordBreak: 'break-all', fontSize: '10px' }}>{i.value}</td>
                      <td><StatusBadge severity={reputationKey(i.reputation)} label={i.reputation} /></td>
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

export default function Alerts({ alerts, loading, error, refreshAlerts, seedSampleAlerts }) {
  const [analysisBusy, setAnalysisBusy] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [fetchingDetail, setFetchingDetail] = useState(false);
  const [ingesting, setIngesting] = useState(false);

  // Client-side filtering
  const filteredAlerts = alerts.filter(a => {
    const sev = (a.severity || a.raw_severity || '').toUpperCase();
    const matchesSev = filterSeverity === 'ALL' || sev === filterSeverity;
    const title = (a.alert_title || a.alert_name || '').toLowerCase();
    const source = (a.source || a.source_system || '').toLowerCase();
    const host = (a.host || a.host_name || '').toLowerCase();
    const user = (a.username || a.user || '').toLowerCase();
    const query = searchQuery.toLowerCase();

    const matchesSearch = title.includes(query) || source.includes(query) || host.includes(query) || user.includes(query);
    return matchesSev && matchesSearch;
  });

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
      alert(`Error ingesting test alert: ${err.message}`);
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
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => (
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
            {error}. Check that the FastAPI backend server is running at <code>http://localhost:8000</code>.
          </p>
          <button 
            onClick={refreshAlerts} 
            style={{ marginTop: '12px', padding: '6px 14px', borderRadius: 'var(--radius-sm)', border: 'none', background: '#ef4444', color: '#fff', fontSize: '12px', fontWeight: 700, cursor: 'pointer' }}
          >
            Retry Connection
          </button>
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
                      ) : 'No security alerts found matching the active search/severity filter.'}
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
                        {new Date(a.timestamp).toLocaleTimeString()}
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
                  </div>

                  <AnalysisPanels alert={selectedAlert} busy={analysisBusy} onRun={handleRunAnalysis} runError={analysisError} />
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
