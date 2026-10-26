import React from 'react';
import { Sliders, Shield, Database, RefreshCw } from 'lucide-react';
import { ActionButton, ErrorCard, LoadingCard } from '../components/StateCards';
import { api, API_BASE } from '../api';
import useAsync from '../lib/useAsync';

const row = { display: 'flex', justifyContent: 'space-between', gap: '16px', padding: '8px 0', borderBottom: '1px solid var(--border-color)', fontSize: '13px' };
const label = { color: 'var(--text-muted)' };

function Row({ name, value, note }) {
  return (
    <div style={row}>
      <span style={label}>{name}</span>
      <span style={{ textAlign: 'right' }}>
        <strong>{value}</strong>
        {note && <div style={{ fontSize: '11px', color: 'var(--text-muted)', maxWidth: '420px' }}>{note}</div>}
      </span>
    </div>
  );
}

/** Read-only view of what the backend is actually configured to do (GET /config). Nothing here is editable. */
export default function Settings() {
  const { loading, error, data: cfg, reload } = useAsync(() => api('/config'), []);

  return (
    <div style={{ maxWidth: '800px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Read-only. These values come from the backend at <code>{API_BASE}</code>; change them with environment variables (see <code>.env.example</code>).
        </span>
        <ActionButton variant="ghost" onClick={reload}><RefreshCw size={12} style={{ verticalAlign: '-2px' }} /> Refresh</ActionButton>
      </div>

      {loading && !cfg && <LoadingCard>Loading configuration...</LoadingCard>}
      {error && <ErrorCard title="Could not load the configuration" message={error} onRetry={reload} />}

      {cfg && (
        <>
          <div className="glass-card" style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <Sliders size={20} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '16px' }}>Analysis Configuration</h3>
            </div>
            <Row name="Threat intelligence" value={cfg.threat_intel.mode === 'mock' ? 'Local mock data' : 'Unavailable (no lookups)'} note={cfg.threat_intel.note} />
            <Row name="Live threat-intelligence provider" value={cfg.threat_intel.live_provider_implemented ? 'Implemented' : 'Not implemented'} />
            <Row name="AI model" value={cfg.llm.used_by_agents ? cfg.llm.configured_provider : 'None used'} note={cfg.llm.note} />
          </div>

          <div className="glass-card" style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <Database size={20} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '16px' }}>Data Sources</h3>
            </div>
            <Row name="Database engine" value={cfg.database_engine} />
            <Row name="Sample alert dataset" value={cfg.sample_alert_dataset} note="Loaded only when you press “Load sample (synthetic) alerts”." />
            <Row name="Investigation log source" value={cfg.investigation_log_source.path} note="A bundled synthetic file. No SIEM or log platform is queried." />
            <Row name="Backend version / environment" value={`${cfg.version} / ${cfg.environment}`} />
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <Shield size={20} color="#10b981" />
              <h3 style={{ fontSize: '16px' }}>Safety Boundaries</h3>
            </div>
            <Row name="Response execution mode" value={cfg.execution_mode} note="Approved responses can only be simulated. No command is run and no system is changed." />
            <Row name="Human approval for responses" value="Required" note="Every recommendation starts PENDING and needs a recorded decision." />
            <Row name="Authentication" value={cfg.authentication.enabled ? 'Enabled' : 'Not enabled'} note={cfg.authentication.note} />
          </div>
        </>
      )}
    </div>
  );
}
