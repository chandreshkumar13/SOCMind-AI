// Pure CSV helpers for the Audit Log export. No React and no DOM here, so they can be unit-tested with `node --test`.
// The export holds the audit entries that are loaded on the page. It is not a server-side export of every matching entry.
import { uniqueById } from './auditLoad.js';

export const AUDIT_CSV_HEADERS = ['Timestamp (UTC)', 'Actor', 'Action', 'Target ID', 'Details'];

// Characters that make a spreadsheet treat a cell as a formula (or, for tab and carriage return, an injected line).
const FORMULA_LEAD = /^\s*[=+\-@]/;
const CONTROL_LEAD = /^ *[\t\r]/;

/**
 * Stops spreadsheet formula injection. A value that starts with = + - @ tab or carriage return (after optional spaces) gets a
 * leading apostrophe, so Excel and similar tools show it as text instead of running it. Harmless text is returned unchanged.
 * Negative numbers such as "-5" are also prefixed: an audit export is text, so that is the safe choice.
 */
export function neutralizeFormula(text) {
  if (FORMULA_LEAD.test(text) || CONTROL_LEAD.test(text)) return `'${text}`;
  return text;
}

/** One CSV field: null and undefined become empty, objects become compact JSON, and the field is quoted when needed (RFC 4180). */
export function csvCell(value) {
  if (value === null || value === undefined) return '';
  let text = typeof value === 'string' ? value : typeof value === 'object' ? JSON.stringify(value) : String(value);
  text = neutralizeFormula(text);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

/** One CSV line. Fields are joined with commas; the caller chooses the line ending. */
export function csvLine(values) {
  return values.map(csvCell).join(',');
}

/**
 * The timestamp as shown in the table: "YYYY-MM-DD HH:MM:SS" (UTC), the same as formatUtc without its suffix, because the column
 * header already says UTC. A value that is not an ISO-like timestamp is kept as it was, rather than guessed at.
 */
export function csvTimestamp(value) {
  if (!value) return '';
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(String(value));
  return m ? `${m[1]} ${m[2]}` : String(value);
}

/**
 * The export: header row, then one row per audit entry, lines separated by CRLF as RFC 4180 specifies. Each audit id appears at
 * most once (the first copy is kept), so a repeated entry from overlapping pages is never exported twice.
 */
export function auditRowsToCsv(rows) {
  const lines = [csvLine(AUDIT_CSV_HEADERS)];
  for (const r of uniqueById(rows)) {
    lines.push(csvLine([csvTimestamp(r.timestamp), r.actor, r.action, r.target_id, r.details]));
  }
  return lines.join('\r\n') + '\r\n';
}

/** The export as a Blob: a UTF-8 byte-order mark (so Excel reads non-ASCII text correctly), then the CSV text. */
export function auditCsvBlob(rows) {
  return new Blob(['\uFEFF', auditRowsToCsv(rows)], { type: 'text/csv;charset=utf-8' });
}

/**
 * How long the object URL stays valid after a download starts. Some browsers cancel the download when the URL is revoked
 * straight after the click, so it is released after this delay instead.
 */
export const REVOKE_DELAY_MS = 1000;

function browserEnv() {
  return {
    createUrl: (blob) => URL.createObjectURL(blob),
    revokeUrl: (url) => URL.revokeObjectURL(url),
    doc: document,
    setTimer: (fn, ms) => setTimeout(fn, ms),
  };
}

/**
 * Starts a download of `blob` under `filename`.
 *
 * The object URL is revoked by exactly one timer, scheduled in the `finally` block. That block runs however far the work got:
 * if creating or appending the anchor, or the click, throws, the URL is still released after REVOKE_DELAY_MS. The anchor is
 * removed whenever it was created, and a failure to remove it is ignored, so it never hides the original error or skips the
 * timer. The error from a failed step still propagates to the caller. `env` is injectable so this can be tested without a browser.
 */
export function downloadBlob(blob, filename, env = browserEnv()) {
  const url = env.createUrl(blob);
  let link = null;
  try {
    link = env.doc.createElement('a');
    link.href = url;
    link.download = filename;
    env.doc.body.appendChild(link);
    link.click();
  } finally {
    if (link) {
      try {
        link.remove();
      } catch {
        // the anchor is a temporary element; a failed removal must not hide the original error or skip the revocation below
      }
    }
    env.setTimer(() => env.revokeUrl(url), REVOKE_DELAY_MS);
  }
  return url;
}

/** File name for the download, dated in UTC: socmind-audit-log-2026-11-10.csv. */
export function auditExportFilename(now = new Date()) {
  const day = now.toISOString().slice(0, 10);
  return `socmind-audit-log-${day}.csv`;
}

/**
 * The sentence shown next to the export button. It states what the file holds: the loaded entries, and whether more matching
 * entries exist on the server that would need "Load older entries" first. While a load has failed, the rows on screen cannot be
 * vouched for, so the note says nothing can be exported instead of describing them.
 */
export function auditExportNote(loadedCount, hasMore, failed = false) {
  if (failed) return 'The audit log could not be loaded, so nothing is exported. Retry the load first.';
  if (!loadedCount) return 'Nothing is loaded yet, so there is nothing to export.';
  const entries = `${loadedCount} entr${loadedCount === 1 ? 'y' : 'ies'}`;
  if (hasMore) {
    return `The export holds the ${entries} loaded so far, not necessarily every entry that matches the filters. Use "Load older entries" to load more first.`;
  }
  return `The export holds all ${entries} that match the filters.`;
}
