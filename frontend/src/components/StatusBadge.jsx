import React from 'react';

// Words that map onto the existing badge colours. Reputation words are deliberately NOT styled as "success":
// a CLEAN result comes from mock intelligence and does not prove an indicator is safe.
const CLASS_BY_WORD = {
  critical: 'badge-critical', malicious: 'badge-critical', failed: 'badge-critical', failure: 'badge-critical', rejected: 'badge-critical',
  high: 'badge-high', suspicious: 'badge-high', partial: 'badge-high',
  medium: 'badge-medium', pending: 'badge-medium',
  success: 'badge-success', new: 'badge-success', active: 'badge-success', approved: 'badge-success', verified: 'badge-success',
};

export default function StatusBadge({ severity, label }) {
  const key = String(severity || 'low').toLowerCase();
  const className = CLASS_BY_WORD[key] || 'badge-low';

  return (
    <span className={`badge ${className}`}>
      {label ?? severity}
    </span>
  );
}
