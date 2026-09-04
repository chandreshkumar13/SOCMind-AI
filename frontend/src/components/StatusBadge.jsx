import React from 'react';

export default function StatusBadge({ severity }) {
  const sev = (severity || 'low').toLowerCase();
  
  let className = 'badge-low';
  if (sev === 'critical') className = 'badge-critical';
  else if (sev === 'high') className = 'badge-high';
  else if (sev === 'medium') className = 'badge-medium';
  else if (sev === 'success' || sev === 'new' || sev === 'active') className = 'badge-success';

  return (
    <span className={`badge ${className}`}>
      {severity}
    </span>
  );
}
