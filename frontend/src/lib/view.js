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

/** Splits investigation findings into the evidence classes the UI must never mix up. */
export function groupFindings(findings) {
  const groups = { verified: [], mock_intel: [], external_intel: [], hypothesis: [] };
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
  if (recommendationView(details).kind === 'superseded') {
    return { canReview: false, reason: 'These recommendations were superseded when an earlier decision was withdrawn. Generate new recommendations first.' };
  }
  if (details.recommendations_stale) {
    return { canReview: false, reason: 'The incident changed after these recommendations were made. Regenerate them first.' };
  }
  if (incident.human_approval_status !== 'PENDING') {
    return { canReview: false, reason: `A decision is already recorded: ${incident.human_approval_status}.` };
  }
  return { canReview: true, reason: '' };
}

/**
 * What the recommendations panel may present. `superseded`: an earlier decision was withdrawn, so these are history and not
 * proposals. `current`: live proposals. `none`: nothing has been generated.
 */
export function recommendationView(details) {
  const recs = Array.isArray(details && details.recommendations) ? details.recommendations.filter(Boolean) : [];
  if (recs.length === 0) return { kind: 'none', recommendations: [], reason: '', supersededAt: null };
  const history = Array.isArray(details.review_history) ? details.review_history : [];
  const last = history.length ? history[history.length - 1] : {};
  // Marked SUPERSEDED when withdrawn. Records withdrawn before that mark existed still carry a decision's marks while no
  // decision is in force (no `review`), so they are history too and must not read as current proposals.
  const legacyWithdrawn = !details.review
    && recs.some((r) => r.status === 'APPROVED' || r.status === 'REJECTED' || r.simulation_status === 'SIMULATED');
  if (legacyWithdrawn || recs.every((r) => r.status === 'SUPERSEDED')) {
    return {
      kind: 'superseded', recommendations: recs,
      reason: recs[0].superseded_by || last.superseded_by || 'the analysis they were based on changed',
      supersededAt: recs[0].superseded_at || last.superseded_at || null,
    };
  }
  return { kind: 'current', recommendations: recs, reason: '', supersededAt: null };
}

/**
 * The warning shown before re-investigating an incident with a recorded decision: the decision (and any simulation of it)
 * is withdrawn and kept in the review history. Null when nothing would be withdrawn (a pending incident).
 */
export function reinvestigationNotice(incident) {
  const decision = incident && incident.human_approval_status;
  if (!decision || decision === 'PENDING') return null;
  const details = (incident && incident.details) || {};
  const reviewer = details.review && details.review.reviewer ? ` by ${details.review.reviewer}` : '';
  const simulation = details.simulation ? ' and its simulation' : '';
  return `The ${String(decision).toLowerCase()} decision${reviewer}${simulation} will be withdrawn and saved in the review history. `
    + 'Its recommendations are marked superseded, and the incident returns to PENDING for a new review. Nothing is executed.';
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

/** Simulation is only possible for a fresh APPROVED decision, and only once. Nothing is ever executed. */
export function simulationState(incident) {
  const details = (incident && incident.details) || {};
  if (details.simulation) return { canSimulate: false, simulated: true, reason: 'This approved response was already simulated.' };
  if (!incident || incident.human_approval_status !== 'APPROVED') {
    return { canSimulate: false, simulated: false, reason: 'Only an approved response can be simulated.' };
  }
  if (details.recommendations_stale) {
    return { canSimulate: false, simulated: false, reason: 'The approved recommendations are out of date. Regenerate and re-approve them.' };
  }
  return { canSimulate: true, simulated: false, reason: '' };
}

/** Query string for GET /audit-logs; empty filters are left out and the action is upper-cased as the API expects. */
export function auditQuery({ actor = '', action = '', target = '', limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams();
  if (actor.trim()) params.set('actor', actor.trim());
  if (action.trim()) params.set('action', action.trim().toUpperCase());
  if (target.trim()) params.set('target_id', target.trim());
  params.set('limit', String(limit));
  params.set('offset', String(offset));
  return `?${params.toString()}`;
}

/** Compact one-line preview of an audit entry's details object. */
export function previewDetails(details, max = 90) {
  if (details === null || details === undefined || details === '') return '';
  const text = typeof details === 'string' ? details : JSON.stringify(details);
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** "Showing 100 of 130" style note when a list is shorter than the true total. */
export function truncationNote(shown, total) {
  return typeof total === 'number' && total > shown ? `Showing the first ${shown} of ${total}.` : '';
}

// The server returns at most this many alerts per request (GET /api/v1/alerts caps limit at 100).
export const SEARCH_RESULT_LIMIT = 100;

/** Request path for a server-side alert search, or null for an empty query. The query is trimmed and URL-encoded. */
export function alertSearchPath(query, limit = SEARCH_RESULT_LIMIT) {
  const term = String(query ?? '').trim();
  if (!term) return null;
  return `/alerts?search=${encodeURIComponent(term)}&limit=${limit}`;
}

/** Note for a search that filled the whole page: there may be more matches than are shown. */
export function searchCapNote(count, limit = SEARCH_RESULT_LIMIT) {
  return count >= limit
    ? `Showing the first ${limit} matches. Results are capped at ${limit}, so refine the search to narrow them.`
    : '';
}

/**
 * The outcome of one server-side alert search, as the page should hold it: the rows for the query, or an error.
 * A failed request carries no rows at all, so rows from an earlier search for the same query are never shown as
 * current matches; the page then falls back to the loaded alerts.
 */
export async function fetchAlertSearch(query, request) {
  const path = alertSearchPath(query);
  if (!path) return { result: null, error: null };
  try {
    const rows = await request(path);
    return { result: { term: String(query).trim(), rows }, error: null };
  } catch (err) {
    return { result: null, error: err?.message || 'request failed' };
  }
}

// ---- threat-intelligence presentation ---------------------------------------------------------------------------
const RETRYABLE_LOOKUPS = ['rate_limited', 'budget_exceeded', 'timeout', 'error', 'circuit_open'];

const LOOKUP_LABELS = {
  completed: 'Looked up',
  not_found: 'Not found (not evidence of safety)',
  rate_limited: 'Quota reached, retry later',
  budget_exceeded: 'Per-alert limit, retry later',
  timeout: 'Timed out, retry later',
  error: 'Failed, retry later',
  circuit_open: 'Paused after failures, retry later',
  auth_error: 'API key rejected',
  skipped_non_public_ip: 'Private or reserved: not sent',
  skipped_invalid: 'Not a public indicator: not sent',
  skipped_url: 'URL lookups are off',
  skipped_unsupported: 'Not looked up',
};

const MOCK_DISCLAIMER_TEXT = 'Results come from LOCAL MOCK threat intelligence, not a verified live feed. A CLEAN or UNKNOWN reputation only means the mock has no malicious record; it does not mean the indicator is verified safe.';
const UNAVAILABLE_DISCLAIMER_TEXT = 'No threat-intelligence lookups were performed, so every reputation means "not checked", not "safe".';

/**
 * Where an enrichment result's reputations really came from. A result is labelled LIVE only when the stored record
 * says intel_mode "live" AND names its provider. Anything less is never presented as live:
 *  - intel_mode "live" without a provider is "unrecorded";
 *  - a record with no intel_mode is the local mock (the only source before live mode existed), unless it names a provider.
 */
export function intelSource(enrichment) {
  if (!enrichment || typeof enrichment !== 'object') return null;
  const mode = enrichment.intel_mode;
  const provider = typeof enrichment.provider === 'string' ? enrichment.provider.trim() : '';
  if (mode === 'live') {
    if (provider) {
      return {
        kind: 'live', live: true, label: `${provider} (live lookup)`, columnLabel: provider, verified: false,
        disclaimer: enrichment.disclaimer || `Reputation reported by ${provider}. It is not independently verified by SOCMind AI and can include false positives. CLEAN, UNKNOWN or 'not found' never mean the indicator is verified safe.`,
      };
    }
    return {
      kind: 'unrecorded', live: false, label: 'Live lookup, provider not recorded', columnLabel: 'unrecorded', verified: false,
      disclaimer: 'The stored record says it used live lookups but does not name the provider, so it is treated as unverified.',
    };
  }
  if (mode === 'unavailable') {
    return {
      kind: 'unavailable', live: false, label: 'Not looked up', columnLabel: 'not looked up', verified: false,
      disclaimer: enrichment.disclaimer || UNAVAILABLE_DISCLAIMER_TEXT,
    };
  }
  if (mode === 'mock' || (!mode && !provider)) {
    return {
      kind: 'mock', live: false, label: 'Local mock (unverified)', columnLabel: 'mock', verified: false,
      disclaimer: enrichment.disclaimer || MOCK_DISCLAIMER_TEXT,
    };
  }
  return {
    kind: 'unrecorded', live: false, label: 'Source not recorded', columnLabel: 'unrecorded', verified: false,
    disclaimer: 'The stored record does not say which source produced these reputations, so they are treated as unverified.',
  };
}

/** Column title: "mock", "VirusTotal", "not looked up" or "unrecorded". */
export function reputationSource(enrichment) {
  const source = intelSource(enrichment);
  return source ? source.columnLabel : 'mock';
}

/** Microsecond-precise sort key for the backend's UTC timestamps; -Infinity when missing or unreadable. */
function timestampKey(value) {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?/.exec(String(value || ''));
  if (!m) return -Infinity;
  const base = Date.parse(`${m[1]}Z`);
  if (Number.isNaN(base)) return -Infinity;
  return base * 1000 + Number((m[2] || '').padEnd(6, '0').slice(0, 6));
}

/**
 * Keeps an open alert record in step with the server. Returns the copy of the same alert from a freshly loaded list
 * when that copy is at least as new; otherwise keeps the open record (it may have been fetched after the list).
 */
export function refreshedSelection(selected, list) {
  if (!selected) return null;
  const fresh = (list || []).find((a) => a && a.id === selected.id);
  if (!fresh) return selected;
  return timestampKey(fresh.updated_at) >= timestampKey(selected.updated_at) ? fresh : selected;
}


export function lookupStatusLabel(status) {
  if (!status) return '';
  return LOOKUP_LABELS[status] || String(status).replace(/_/g, ' ');
}

export function isRetryableLookup(status) {
  return RETRYABLE_LOOKUPS.includes(status);
}

/** "3/72 engines flagged" from a detections object, or '' when there is none. */
export function detectionLabel(detections) {
  if (!detections || !detections.total) return '';
  return `${(detections.malicious || 0) + (detections.suspicious || 0)}/${detections.total} engines flagged`;
}

/** Only ever link to VirusTotal's own report pages; anything else coming back from the API is dropped. */
export function safeVirusTotalUrl(url) {
  return typeof url === 'string' && /^https:\/\/www\.virustotal\.com\/gui\/[A-Za-z0-9:._/-]+$/.test(url) ? url : null;
}

/** Plain-language notes about an enrichment result that an analyst must not miss. */
export function enrichmentNotices(enrichment) {
  if (!enrichment) return [];
  const notes = [];
  if (enrichment.fallback_reason) notes.push(`Live lookups were requested but are not active: ${enrichment.fallback_reason}`);
  if (enrichment.intel_mode === 'unavailable') notes.push('No lookups were performed, so every reputation is "not checked".');
  if (enrichment.incomplete) notes.push('Some indicators could not be checked yet (request quota, per-alert limit or provider errors). Run the pipeline or enrichment again later to complete them.');
  return notes;
}
