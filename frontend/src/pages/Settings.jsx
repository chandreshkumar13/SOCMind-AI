import React, { useState } from 'react';
import { Sliders, Shield, Database, RefreshCw } from 'lucide-react';
import { ActionButton, ErrorCard, LoadingCard } from '../components/StateCards';
import { api, API_BASE, readStoredToken, storeToken } from '../api';
import useAsync from '../lib/useAsync';
import { describeAccessError } from '../lib/view';

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

// Sign-in for token mode. The token is kept for this browser tab only (see api.js) and is never shown back in full.
function AccessCard() {
  const [draft, setDraft] = useState('');
  const [saved, setSaved] = useState(() => readStoredToken() !== '');
  const [who, setWho] = useState(null);
  const [message, setMessage] = useState('');

  const check = async () => {
    try {
      setWho(await api('/auth/me'));
      setMessage('');
    } catch (err) {
      setWho(null);
      setMessage(err.message || describeAccessError(err.status));
    }
  };

  const save = async () => {
    storeToken(draft);
    setSaved(draft.trim() !== '');
    setDraft('');
    await check();
  };

  const clear = () => {
    storeToken('');
    setSaved(false);
    setWho(null);
    setMessage('');
  };

  const input = { padding: '6px 10px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-main)', fontSize: '13px', minWidth: '260px' };
  return (
    <div className="glass-card" style={{ marginBottom: '20px' }}>
      <h3 style={{ fontSize: '15px', marginBottom: '8px' }}>Access</h3>
      <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '10px' }}>
        If the server runs in token mode, paste your access token here. It is kept for this browser tab only and is cleared when the tab closes.
        In demo mode no token is needed.
      </p>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        <input type="password" autoComplete="off" aria-label="Access token" placeholder={saved ? 'A token is saved for this tab' : 'Access token'}
          value={draft} onChange={(e) => setDraft(e.target.value)} style={input} />
        <ActionButton onClick={save}>Save and check</ActionButton>
        <ActionButton variant="ghost" onClick={clear}>Clear token</ActionButton>
        <ActionButton variant="ghost" onClick={check}>Check access</ActionButton>
      </div>
      {who && (
        <div style={{ fontSize: '13px', marginTop: '10px' }}>
          {who.authenticated ? <>Signed in as <strong>{who.name}</strong> with the <strong>{who.role}</strong> role.</>
            : <>Demo mode: no sign-in needed. Actions are allowed and reviewer names are self-asserted.</>}
        </div>
      )}
      {message && <div style={{ fontSize: '12px', color: '#f87171', marginTop: '8px' }}>{message}</div>}
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
          Read-only configuration. These values come from the backend at <code>{API_BASE}</code>; change them with environment variables (see <code>.env.example</code>).
        </span>
        <ActionButton variant="ghost" onClick={reload}><RefreshCw size={12} style={{ verticalAlign: '-2px' }} /> Refresh</ActionButton>
      </div>

      <AccessCard />

      {loading && !cfg && <LoadingCard>Loading configuration...</LoadingCard>}
      {error && <ErrorCard title="Could not load the configuration" message={error} onRetry={reload} />}

      {cfg && (
        <>
          <div className="glass-card" style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <Sliders size={20} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '16px' }}>Analysis Configuration</h3>
            </div>
            <Row name="Threat intelligence" value={{ live: 'VirusTotal (live lookups)', mock: 'Local mock data', unavailable: 'Unavailable (no lookups)' }[cfg.threat_intel.mode]} note={cfg.threat_intel.note} />
            <Row name="Provider requested / active" value={`${cfg.threat_intel.requested_provider} / ${cfg.threat_intel.active_provider}`} note={cfg.threat_intel.fallback_reason || undefined} />
            <Row name="VirusTotal API key" value={cfg.threat_intel.virustotal.api_key_configured ? 'Configured' : 'Not configured'} note="Only whether a key exists is shown. The key itself is never returned by the API or displayed." />
            <Row name="VirusTotal limits" value={`${cfg.threat_intel.virustotal.requests_per_minute}/min · ${cfg.threat_intel.virustotal.requests_per_day}/day · ${cfg.threat_intel.virustotal.max_lookups_per_alert} per alert`}
              note={`MALICIOUS needs ${cfg.threat_intel.virustotal.malicious_threshold}+ detections. Private/reserved addresses and URLs are never sent. Timeout ${cfg.threat_intel.virustotal.timeout_seconds}s.`} />
            {cfg.threat_intel.virustotal.quota && (
              <Row name="Quota used (rolling)" value={`${cfg.threat_intel.virustotal.quota.used_last_minute}/${cfg.threat_intel.virustotal.quota.per_minute} last minute · ${cfg.threat_intel.virustotal.quota.used_last_24h}/${cfg.threat_intel.virustotal.quota.per_day} last 24 h`}
                note={cfg.threat_intel.virustotal.quota.paused_for_seconds ? `Paused for about ${cfg.threat_intel.virustotal.quota.paused_for_seconds} s after a rate-limit answer.` : undefined} />
            )}
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
