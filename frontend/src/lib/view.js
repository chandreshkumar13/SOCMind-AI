// Pure helpers shared by the pages. No React and no import.meta here, so they can be unit-tested with `node --test`.

/** Readable message from a FastAPI error body (string detail, validation-error list, or nothing). */
export function describeError(status, body) {
  const detail = body && body.detail;
  if (typeof detail === 'string' && detail) return detail;
  if (Array.isArray(detail) && detail.length) {
    return detail
      .map((d) => {
        const field = Array.isArray(d.loc) ? d.loc.filter((p) => p !== 'body').join('.') : '';
        return field ? `${field}: ${d.msg}` : d.msg;
      })
      .join('; ');
  }
  if (body && typeof body.message === 'string' && body.message) return body.message;
  return `Request failed (HTTP ${status})`;
}

/** Splits investigation findings into the three evidence classes the UI must never mix up. */
export function groupFindings(findings) {
  const groups = { verified: [], mock_intel: [], hypothesis: [] };
  for (const f of findings || []) {
    if (groups[f.type]) groups[f.type].push(f);
  }
  return groups;
}

/** Badge colour key understood by StatusBadge. */
export function reputationKey(reputation) {
  return { MALICIOUS: 'critical', SUSPICIOUS: 'high', CLEAN: 'low', UNKNOWN: 'low' }[String(reputation || '').toUpperCase()] || 'low';
}

const STATUS_LABELS = {
  OPEN: 'Open',
  INVESTIGATED: 'Investigated',
  RESPONSE_PROPOSED: 'Response proposed',
  RESPONSE_APPROVED: 'Response approved',
  RESPONSE_REJECTED: 'Response rejected',
  MERGED: 'Merged',
};

export function statusLabel(status) {
  if (!status) return 'Unknown';
  return STATUS_LABELS[status] || String(status).replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}

/** A decision can be recorded only on a fresh recommendation that nobody has decided yet. */
export function reviewState(incident) {
  const details = (incident && incident.details) || {};
  if (!details.recommendations || details.recommendations.length === 0) {
    return { canReview: false, reason: 'No recommendation yet. Generate recommendations first.' };
  }
  if (details.recommendations_stale) {
    return { canReview: false, reason: 'The incident changed after these recommendations were made. Regenerate them first.' };
  }
  if (incident.human_approval_status !== 'PENDING') {
    return { canReview: false, reason: `A decision is already recorded: ${incident.human_approval_status}.` };
  }
  return { canReview: true, reason: '' };
}

/** "2026-09-03T08:14:00Z" -> "2026-09-03 08:14:00 UTC"; unknown stays unknown (never invented). */
export function formatUtc(value) {
  if (!value) return 'time unknown';
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(String(value));
  return m ? `${m[1]} ${m[2]} UTC` : String(value);
}

/** One-line summary of a pipeline run for lists. */
export function summarizeRun(run) {
  if (!run) return '';
  const failed = (run.stages || []).filter((s) => s.status === 'failed' || s.status === 'partial').length;
  const base = `${run.alerts_in_scope} alert(s) in scope, ${(run.incidents_created || []).length} incident(s) created`;
  return failed ? `${base}, ${failed} stage(s) with errors` : base;
}

export function runBadgeKey(outcome) {
  return { success: 'success', partial: 'high', failure: 'critical' }[outcome] || 'low';
}

export function stageBadgeKey(status) {
  return { success: 'success', partial: 'high', failed: 'critical' }[status] || 'low';
}
