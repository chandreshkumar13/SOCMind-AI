// Search, filtering and sorting for the Correlated Incidents list. No React and no DOM, so the rules are unit-tested
// with Node's built-in test runner (incidentFilters.test.js). They run in the browser on the incidents the page already
// received and never change data. MERGED incidents are folded into another incident, so they are never listed or counted.

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const APPROVAL_FILTERS = ['ALL', 'PENDING', 'APPROVED', 'REJECTED'];
export const STATUS_FILTERS = [
  'ALL', 'OPEN', 'INVESTIGATED', 'RESPONSE_PROPOSED', 'RESPONSE_APPROVED', 'RESPONSE_REJECTED', 'RESPONSE_SIMULATED',
];
export const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest first' },
  { value: 'oldest', label: 'Oldest first' },
  { value: 'severity', label: 'Highest severity' },
  { value: 'alerts', label: 'Most alerts' },
];
export const DEFAULT_CRITERIA = Object.freeze({ search: '', severity: 'ALL', approval: 'ALL', status: 'ALL', sort: 'newest' });

const upper = (value) => String(value ?? '').trim().toUpperCase();
const list = (value) => (Array.isArray(value) ? value : []);

/**
 * Microseconds since the epoch for an ISO-8601 UTC timestamp such as "2026-10-22T14:18:05.601364Z". Microseconds are kept
 * so incidents created a fraction of a second apart still order correctly; the value stays exact in a JavaScript number.
 * null when the value is missing or is not a UTC timestamp, so it can sort last.
 */
export function timeValue(value) {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z?$/.exec(String(value ?? '').trim());
  if (!m) return null;
  const ms = Date.parse(`${m[1]}Z`);
  if (Number.isNaN(ms)) return null;
  return ms * 1000 + Number((m[2] || '').padEnd(6, '0').slice(0, 6));
}

/** The incidents the list is about: everything except MERGED ones. */
export function activeIncidents(incidents) {
  return list(incidents).filter((i) => i && typeof i === 'object' && i.status !== 'MERGED');
}

/**
 * The text the search box is matched against: id, title, AI summary, and the hosts, users and IPs of the investigation
 * entities. Each field is checked on its own, so a search term can never match across two fields.
 */
export function searchableFields(incident) {
  const entities = incident?.details?.investigation?.entities ?? {};
  const values = [
    incident.id, incident.title, incident.ai_summary,
    ...list(entities.hosts), ...list(entities.users), ...list(entities.ips),
  ];
  return values.filter((v) => typeof v === 'string' && v.length > 0);
}

/** Case-insensitive, ignoring leading and trailing spaces. An empty search matches everything. */
export function matchesSearch(incident, search) {
  const term = String(search ?? '').trim().toLowerCase();
  if (!term) return true;
  return searchableFields(incident).some((field) => field.toLowerCase().includes(term));
}

/** Every active filter must match (AND). "ALL" means the filter is off. */
export function matchesFilters(incident, criteria = {}) {
  const c = { ...DEFAULT_CRITERIA, ...criteria };
  if (upper(c.severity) !== 'ALL' && upper(incident.severity) !== upper(c.severity)) return false;
  if (upper(c.approval) !== 'ALL' && upper(incident.human_approval_status) !== upper(c.approval)) return false;
  if (upper(c.status) !== 'ALL' && upper(incident.status) !== upper(c.status)) return false;
  return matchesSearch(incident, c.search);
}

/** Position in SEVERITY_ORDER (CRITICAL first). Unknown or missing severities sort after INFO. */
export function severityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(upper(severity));
  return index === -1 ? SEVERITY_ORDER.length : index;
}

function alertCount(incident) {
  return list(incident.correlated_alert_ids).length;
}

// Missing or unreadable times always sort last, whichever direction is chosen.
function compareTime(a, b, direction) {
  const x = timeValue(a.created_at);
  const y = timeValue(b.created_at);
  if (x === null || y === null) return x === y ? 0 : x === null ? 1 : -1;
  return direction * (x - y);
}

// Ties are broken by incident id (ascending), so every ordering is deterministic.
function compareId(a, b) {
  const x = String(a.id);
  const y = String(b.id);
  return x < y ? -1 : x > y ? 1 : 0;
}

const comparators = {
  newest: (a, b) => compareTime(a, b, -1) || compareId(a, b),
  oldest: (a, b) => compareTime(a, b, 1) || compareId(a, b),
  severity: (a, b) => severityRank(a.severity) - severityRank(b.severity) || compareId(a, b),
  alerts: (a, b) => alertCount(b) - alertCount(a) || compareId(a, b),
};

/** The list as shown: non-MERGED incidents that match every filter, in the chosen order. The input is not changed. */
export function filterAndSortIncidents(incidents, criteria = {}) {
  const c = { ...DEFAULT_CRITERIA, ...criteria };
  const compare = comparators[c.sort] || comparators.newest;
  return activeIncidents(incidents).filter((i) => matchesFilters(i, c)).sort(compare);
}

/** True when the view is the default one (no search, no filters, default sort): what "Clear filters" returns to. */
export function isDefaultView(criteria = {}) {
  const c = { ...DEFAULT_CRITERIA, ...criteria };
  return String(c.search ?? '').trim() === ''
    && upper(c.severity) === 'ALL'
    && upper(c.approval) === 'ALL'
    && upper(c.status) === 'ALL'
    && c.sort === DEFAULT_CRITERIA.sort;
}

/** "Showing 3 of 12 incidents". `total` counts the non-MERGED incidents. */
export function shownSummary(shown, total) {
  return `Showing ${shown} of ${total} incident${total === 1 ? '' : 's'}`;
}
