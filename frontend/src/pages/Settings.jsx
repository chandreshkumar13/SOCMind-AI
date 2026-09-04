import React from 'react';
import { Sliders, Shield, Database, Key, Check } from 'lucide-react';

export default function Settings() {
  return (
    <div style={{ maxWidth: '800px' }}>
      <div className="glass-card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <Sliders size={20} color="var(--accent-cyan)" />
          <h3 style={{ fontSize: '16px' }}>AI Model Provider Configuration</h3>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '13px' }}>
          <div>
            <label style={{ display: 'block', color: 'var(--text-muted)', marginBottom: '6px' }}>LLM Model Provider</label>
            <select style={{
              width: '100%',
              padding: '8px 12px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-color)',
              background: 'var(--bg-dark)',
              color: 'var(--text-main)'
            }}>
              <option value="mock">Mock Intelligence Provider (Default Academic Safe Mode)</option>
              <option value="gemini">Google Gemini API (via Environment Variable)</option>
              <option value="openai">OpenAI GPT-4 API (via Environment Variable)</option>
              <option value="ollama">Local Ollama LLM</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', color: 'var(--text-muted)', marginBottom: '6px' }}>Synthetic Dataset Path</label>
            <input 
              type="text" 
              readOnly 
              value="data/sample_alerts/synthetic_alerts.json" 
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-color)',
                background: 'var(--bg-dark)',
                color: 'var(--accent-cyan)',
                fontFamily: 'var(--font-mono)'
              }}
            />
          </div>
        </div>
      </div>

      <div className="glass-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <Shield size={20} color="#10b981" />
          <h3 style={{ fontSize: '16px' }}>Academic Safety & Guardrails</h3>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Check size={16} color="#10b981" />
            <span>Human Approval Requirement for Remediation: <strong>STRICTLY ENFORCED</strong></span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Check size={16} color="#10b981" />
            <span>Synthetic / Public Threat Data Isolation: <strong>ACTIVE</strong></span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Check size={16} color="#10b981" />
            <span>No Uncontrolled Destructive Commands: <strong>VERIFIED</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
}
