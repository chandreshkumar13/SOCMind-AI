import React from 'react';
import { formatUtc, recommendationView } from '../lib/view';

const panel = { background: 'rgba(0, 0, 0, 0.2)', padding: '12px 16px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(234, 179, 8, 0.4)', marginBottom: '14px' };

/**
 * Shown on an incident whose investigation or recommendations were built on evidence that has since changed (new correlated
 * alerts, or a material change to an alert's threat-intelligence results), and on recommendations that were superseded when
 * an earlier decision was withdrawn. Renders nothing when the incident is current.
 */
export default function StaleNotice({ details }) {
  if (!details) return null;
  const view = recommendationView(details);
  const superseded = view.kind === 'superseded';
  // Superseded recommendations are explained on their own: they were not made stale by changed data
  const outOfDate = Boolean(details.investigation_stale || (details.recommendations_stale && !superseded));
  if (!superseded && !outOfDate) return null;
  const parts = [];
  if (details.investigation_stale) parts.push('the investigation');
  if (details.recommendations_stale && !superseded) parts.push('the recommendations');
  const reasons = Array.isArray(details.stale_reasons) ? details.stale_reasons.slice(-5) : [];
  const when = view.supersededAt ? ` ${formatUtc(view.supersededAt)}` : '';
  return (
    <>
      {superseded && (
        <div style={{ ...panel, color: 'var(--text-muted)', borderColor: 'rgba(148, 163, 184, 0.4)', fontSize: '12px' }}>
          <strong>Recommendations superseded:</strong> an earlier decision was withdrawn{when}: {view.reason}.
          {' '}The recommendations listed are history, not current proposals. Generate new recommendations before deciding.
        </div>
      )}
      {outOfDate && (
        <div style={{ ...panel, color: '#fde047', fontSize: '12px' }}>
          <strong>Out of date:</strong> alert data or threat intelligence changed after {parts.join(' and ')} were produced.
          {' '}Run the pipeline or re-investigate to refresh them before deciding.
          {reasons.length > 0 && (
            <ul style={{ margin: '6px 0 0 18px', color: 'var(--text-muted)' }}>
              {reasons.map((r, i) => (
                <li key={i}>{r.alert_id ? `${r.alert_id}: ` : ''}{r.change}{r.at ? ` (${formatUtc(r.at)})` : ''}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </>
  );
}
