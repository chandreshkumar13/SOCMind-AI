import React, { useCallback, useEffect, useState } from 'react';
import { Download, RefreshCw } from 'lucide-react';
import { ActionButton, EmptyCard, ErrorCard, LoadingCard } from '../components/StateCards';
import { api } from '../api';
import { auditQuery, formatUtc, previewDetails } from '../lib/view';
import { auditCsvBlob, auditExportFilename, auditExportNote, downloadBlob } from '../lib/auditCsv';
import { beginRequest, createRequestGate, initialList, receive } from '../lib/auditLoad';

const PAGE = 50;
const input = { padding: '8px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px' };

/** Read-only view of GET /audit-logs: who did what to which alert or incident, newest first. */
export default function AuditLog() {
  const [filters, setFilters] = useState({ actor: '', action: '', target: '' });
  const [applied, setApplied] = useState(filters);
  const [list, setList] = useState(initialList);
  const [gate] = useState(createRequestGate);       // numbers the requests; only the newest may change the list
  const { rows, hasMore, error, loading, nextOffset } = list;   // nextOffset: where the server's paging has reached

  const load = useCallback(async (query, offset) => {
    const id = gate.start();
    setList(beginRequest);
    try {
      const page = await api(`/audit-logs${auditQuery({ ...query, limit: PAGE, offset })}`);
      setList((state) => receive(gate, id, state, { offset, page }, PAGE));
    } catch (err) {
      setList((state) => receive(gate, id, state, { offset, error: err.message }, PAGE));
    }
  }, [gate]);

  useEffect(() => { load(applied, 0); }, [applied, load]);

  const apply = (e) => { e.preventDefault(); setApplied({ ...filters }); };
  const set = (key) => (e) => setFilters((f) => ({ ...f, [key]: e.target.value }));

  // Exports the entries loaded on this page, with the filters that were applied to them. Never while a load is running or failed.
  const exportCsv = () => downloadBlob(auditCsvBlob(rows), auditExportFilename());

  return (
    <div>
      <form className="glass-card" onSubmit={apply} style={{ marginBottom: '16px', display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input style={input} placeholder="Actor (exact), e.g. Triage Agent" value={filters.actor} onChange={set('actor')} />
        <input style={input} placeholder="Action, e.g. INCIDENT_APPROVED" value={filters.action} onChange={set('action')} />
        <input style={input} placeholder="Target id, e.g. INC-2026-001" value={filters.target} onChange={set('target')} />
        <ActionButton onClick={apply}>Apply filters</ActionButton>
        <ActionButton variant="ghost" onClick={() => { const empty = { actor: '', action: '', target: '' }; setFilters(empty); setApplied(empty); }}>Clear</ActionButton>
        <ActionButton variant="ghost" onClick={() => load(applied, 0)}><RefreshCw size={12} style={{ verticalAlign: '-2px' }} /> Refresh</ActionButton>
      </form>

      {error && <ErrorCard title="Could not load the audit log" message={error} onRetry={() => load(applied, 0)} />}
      {loading && rows.length === 0 && <LoadingCard>Loading audit log...</LoadingCard>}
      {!loading && !error && rows.length === 0 && <EmptyCard title="No audit entries match">Entries appear as alerts are ingested, analysed and reviewed.</EmptyCard>}

      {rows.length > 0 && (
        <div className="table-container">
          <table className="cyber-table">
            <thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="code-font" style={{ fontSize: '12px', whiteSpace: 'nowrap' }}>{formatUtc(r.timestamp)}</td>
                  <td style={{ fontWeight: 600 }}>{r.actor}</td>
                  <td className="code-font">{r.action}</td>
                  <td className="code-font">{r.target_id || '–'}</td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '420px' }}>
                    {r.details === null || r.details === undefined ? '–' : (
                      <details>
                        <summary style={{ cursor: 'pointer' }}>{previewDetails(r.details)}</summary>
                        <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginTop: '6px', fontSize: '11px' }}>
                          {typeof r.details === 'string' ? r.details : JSON.stringify(r.details, null, 2)}
                        </pre>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div style={{ marginTop: '12px', display: 'flex', gap: '12px', alignItems: 'center' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{rows.length} entr{rows.length === 1 ? 'y' : 'ies'} loaded, newest first.</span>
        {hasMore && <ActionButton variant="ghost" busy={loading} onClick={() => load(applied, nextOffset)}>Load older entries</ActionButton>}
        <ActionButton variant="ghost" disabled={rows.length === 0 || loading || Boolean(error)}
          title={error ? 'Export is unavailable while the audit log has a load error' : rows.length === 0 ? 'Nothing loaded to export' : ''}
          onClick={exportCsv}>
          <Download size={12} style={{ verticalAlign: '-2px' }} /> Export CSV
        </ActionButton>
      </div>
      <div style={{ marginTop: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>{auditExportNote(rows.length, hasMore, Boolean(error))}</div>
    </div>
  );
}
