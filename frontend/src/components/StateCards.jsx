import React from 'react';
import { AlertTriangle } from 'lucide-react';

export function LoadingCard({ children }) {
  return (
    <div className="glass-card" style={{ padding: '32px', textAlign: 'center', color: 'var(--accent-cyan)', fontSize: '14px', fontWeight: 600 }}>
      {children || 'Loading...'}
    </div>
  );
}

export function ErrorCard({ title = 'Request failed', message, onRetry }) {
  return (
    <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid #ef4444', marginBottom: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#ef4444', fontWeight: 700, fontSize: '14px' }}>
        <AlertTriangle size={18} />
        {title}
      </div>
      <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '6px' }}>{message}</p>
      {onRetry && (
        <button onClick={onRetry} style={{ marginTop: '10px', padding: '6px 14px', borderRadius: 'var(--radius-sm)', border: 'none', background: '#ef4444', color: '#fff', fontSize: '12px', fontWeight: 700, cursor: 'pointer' }}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyCard({ title, children }) {
  return (
    <div className="glass-card" style={{ padding: '32px', textAlign: 'center' }}>
      <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '6px' }}>{title}</div>
      <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{children}</div>
    </div>
  );
}

export function ActionButton({ onClick, busy, disabled, children, variant = 'primary', title }) {
  const styles = {
    primary: { background: 'linear-gradient(135deg, #00f2fe, #4facfe)', color: '#090d16', border: 'none' },
    approve: { background: '#10b981', color: '#ffffff', border: 'none' },
    ghost: { background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border-color)' },
    danger: { background: 'transparent', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.5)' },
  }[variant];
  return (
    <button
      onClick={onClick}
      disabled={busy || disabled}
      title={title}
      style={{
        padding: '8px 14px', borderRadius: 'var(--radius-sm)', fontWeight: 700, fontSize: '12px',
        cursor: busy ? 'wait' : disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.5 : 1, ...styles,
      }}
    >
      {busy ? 'Working...' : children}
    </button>
  );
}
