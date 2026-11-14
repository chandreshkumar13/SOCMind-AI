// Pure filtering and close-action helpers for the Alerts page (no React, no DOM), so they can be unit-tested with `node --test`.
// Same idea as incidentFilters.js: the page keeps the state, these functions decide what is shown.

export const SEVERITY_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

// The alert statuses the backend actually sets, in the order an alert moves through them:
//   NEW (ingest) -> TRIAGED (triage) -> ENRICHED (enrichment, services/pipeline_steps.py) -> CORRELATED and INVESTIGATING
//   (services/incident_service.py) ... and CLOSED (DELETE /alerts/{id}), which is final.
export const STATUS_FILTERS = ['ALL', 'NEW', 'TRIAGED', 'ENRICHED', 'CORRELATED', 'INVESTIGATING', 'CLOSED'];

// Shown before an alert is closed. The backend marks the alert CLOSED (it is never deleted), removes it from active incidents,
// and cannot reopen it. Nothing else happens: no response action is executed.
export const CLOSE_CONFIRMATION =
  'This marks the alert CLOSED and removes it from active incidents. It cannot be reopened. Nothing is executed.';

/** Severity as the table shows it, upper-case. A record without one has none of the severities. */
export function alertSeverity(alert) {
  return String((alert && (alert.severity || alert.raw_severity)) || '').toUpperCase();
}

/** Status as the table shows it, upper-case. The page has always shown a missing status as NEW. */
export function alertStatus(alert) {
  return String((alert && alert.status) || 'NEW').toUpperCase();
}

/** True for an alert that is already CLOSED. Closed alerts are never reopened. */
export function isAlertClosed(alert) {
  return alertStatus(alert) === 'CLOSED';
}

// Search over the fields an analyst is likely to type: title, source, host, user, alert ID and IP addresses.
// Case-insensitive, ignores surrounding spaces, and an empty query matches every alert.
export function alertMatchesSearch(alert, searchQuery) {
  const query = searchQuery.trim().toLowerCase();
  const fields = [
    alert.alert_title || alert.alert_name, alert.source || alert.source_system, alert.host || alert.host_name,
    alert.username || alert.user, alert.id, alert.source_ip, alert.destination_ip,
  ];
  return fields.some((field) => String(field || '').toLowerCase().includes(query));
}

/**
 * The alerts to show. Severity, status and search all have to match (AND).
 *
 * `serverMatches` is the result of the server-side search, or null. While it is set it replaces the loaded list and the local
 * search is skipped, because the server has already matched every alert; severity and status still narrow it. Without it, the
 * loaded list is searched locally, so the table never goes blank while a search is pending or after it fails.
 */
export function filterAlerts(alerts, criteria = {}, serverMatches = null) {
  const wantedSeverity = String(criteria.severity || 'ALL').toUpperCase();
  const wantedStatus = String(criteria.status || 'ALL').toUpperCase();
  const search = typeof criteria.search === 'string' ? criteria.search : '';
  const source = serverMatches || alerts || [];
  return source.filter((alert) => {
    if (wantedSeverity !== 'ALL' && alertSeverity(alert) !== wantedSeverity) return false;
    if (wantedStatus !== 'ALL' && alertStatus(alert) !== wantedStatus) return false;
    return serverMatches !== null || alertMatchesSearch(alert, search);
  });
}

/** Text for an option of the status filter: "Any status", "New", "Investigating", ... */
export function statusFilterLabel(value) {
  if (value === 'ALL') return 'Any status';
  return value.charAt(0) + value.slice(1).toLowerCase();
}
