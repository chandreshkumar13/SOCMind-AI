import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIT_CSV_HEADERS, neutralizeFormula, csvCell, csvLine, csvTimestamp, auditRowsToCsv, auditExportFilename, auditExportNote,
  auditCsvBlob, downloadBlob, REVOKE_DELAY_MS,
} from './auditCsv.js';

test('the header row is the five agreed columns, in order', () => {
  assert.deepEqual(AUDIT_CSV_HEADERS, ['Timestamp (UTC)', 'Actor', 'Action', 'Target ID', 'Details']);
  assert.equal(auditRowsToCsv([]), 'Timestamp (UTC),Actor,Action,Target ID,Details\r\n');
});

test('commas, quotes and line breaks force quoting, and quotes are doubled', () => {
  assert.equal(csvCell('plain text'), 'plain text');
  assert.equal(csvCell('a, b'), '"a, b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('line one\nline two'), '"line one\nline two"');
  assert.equal(csvCell('windows\r\nbreak'), '"windows\r\nbreak"');
  assert.equal(csvCell('bare\rreturn'), '"bare\rreturn"');
});

test('null and undefined are empty cells, and objects are written as compact JSON', () => {
  assert.equal(csvCell(null), '');
  assert.equal(csvCell(undefined), '');
  assert.equal(csvCell({ status: 'APPROVED', by: 'Ana' }), '"{""status"":""APPROVED"",""by"":""Ana""}"');
  assert.equal(csvCell(42), '42');
});

test('values that start with = + - @ tab or carriage return get a leading apostrophe', () => {
  assert.equal(neutralizeFormula('=cmd|calc'), "'=cmd|calc");
  assert.equal(neutralizeFormula('+1+1'), "'+1+1");
  assert.equal(neutralizeFormula('-2'), "'-2");
  assert.equal(neutralizeFormula('@SUM(A1)'), "'@SUM(A1)");
  assert.equal(neutralizeFormula('\tcalc'), "'\tcalc");
  assert.equal(neutralizeFormula('\rcalc'), "'\rcalc");
});

test('a formula hidden behind leading spaces is also neutralised, and harmless text is not changed', () => {
  assert.equal(neutralizeFormula('   =HYPERLINK("x")'), "'   =HYPERLINK(\"x\")");
  assert.equal(neutralizeFormula('Triage Agent'), 'Triage Agent');
  assert.equal(neutralizeFormula('INC-2026-001'), 'INC-2026-001');
  assert.equal(neutralizeFormula('a=b'), 'a=b');
});

test('leading spaces before a tab or a carriage return are neutralised too', () => {
  assert.equal(neutralizeFormula('   \tcalc'), "'   \tcalc");
  assert.equal(neutralizeFormula('   \rcalc'), "'   \rcalc");
  assert.equal(csvCell('   \rcalc'), `"'   \rcalc"`);      // the carriage return also forces quoting
});

test('an injected formula that also contains a comma is neutralised and then quoted', () => {
  assert.equal(csvCell('=A1,B1'), `"'=A1,B1"`);
});

test('a formula value in an exported row is never left as a live formula', () => {
  const csv = auditRowsToCsv([{ timestamp: '2026-11-10T09:00:00', actor: '=evil()', action: 'INCIDENT_APPROVED', target_id: '+INC', details: '-2+3' }]);
  const row = csv.split('\r\n')[1];
  assert.equal(row, "2026-11-10 09:00:00,'=evil(),INCIDENT_APPROVED,'+INC,'-2+3");
});

test('timestamps are shown as the table shows them, and an unrecognised value is kept as it was', () => {
  assert.equal(csvTimestamp('2026-11-10T09:15:30.123456'), '2026-11-10 09:15:30');
  assert.equal(csvTimestamp('2026-11-10T09:15:30Z'), '2026-11-10 09:15:30');
  assert.equal(csvTimestamp('not a time'), 'not a time');
  assert.equal(csvTimestamp(null), '');
});

test('each entry becomes one row, with CRLF line endings and a trailing newline', () => {
  const csv = auditRowsToCsv([
    { id: 1, timestamp: '2026-11-10T09:00:00', actor: 'Triage Agent', action: 'TRIAGED', target_id: 'ALT-1', details: 'score 72, high' },
    { id: 2, timestamp: '2026-11-10T10:00:00', actor: 'Ana', action: 'INCIDENT_APPROVED', target_id: null, details: { note: 'ok' } },
  ]);
  assert.equal(csv, [
    'Timestamp (UTC),Actor,Action,Target ID,Details',
    '2026-11-10 09:00:00,Triage Agent,TRIAGED,ALT-1,"score 72, high"',
    '2026-11-10 10:00:00,Ana,INCIDENT_APPROVED,,"{""note"":""ok""}"',
    '',
  ].join('\r\n'));
});

test('the rows helper does not change the entries it is given', () => {
  const rows = [{ timestamp: '2026-11-10T09:00:00', actor: '=x', action: 'A', target_id: 'T', details: null }];
  const before = JSON.stringify(rows);
  auditRowsToCsv(rows);
  assert.equal(JSON.stringify(rows), before);
});

test('csvLine joins fields with commas and applies the same escaping', () => {
  assert.equal(csvLine(['a', 'b,c', null]), 'a,"b,c",');
});

test('the file name is dated in UTC', () => {
  assert.equal(auditExportFilename(new Date('2026-11-10T23:30:00Z')), 'socmind-audit-log-2026-11-10.csv');
  assert.equal(auditExportFilename(new Date('2026-11-10T00:00:00Z')), 'socmind-audit-log-2026-11-10.csv');
});

test('the note says the export holds loaded entries, and only claims completeness when nothing more is on the server', () => {
  const partial = auditExportNote(50, true);
  assert.match(partial, /50 entries loaded so far/);
  assert.match(partial, /not necessarily every entry/);
  assert.match(partial, /Load older entries/);
  const complete = auditExportNote(1, false);
  assert.equal(complete, 'The export holds all 1 entry that match the filters.');
  assert.doesNotMatch(complete, /not necessarily/);
});

test('the note for an empty page says there is nothing to export', () => {
  assert.equal(auditExportNote(0, false), 'Nothing is loaded yet, so there is nothing to export.');
});

test('a failed load says nothing can be exported, whatever the rows on screen', () => {
  assert.equal(auditExportNote(50, true, true), 'The audit log could not be loaded, so nothing is exported. Retry the load first.');
  assert.equal(auditExportNote(0, false, true), 'The audit log could not be loaded, so nothing is exported. Retry the load first.');
  assert.doesNotMatch(auditExportNote(3, false, true), /all 3 entries/);
});

test('the CSV blob starts with a UTF-8 byte-order mark and carries the UTF-8 text, including non-ASCII characters', async () => {
  const blob = auditCsvBlob([{ timestamp: '2026-11-10T09:00:00', actor: 'Zoë Ng', action: 'NOTE', target_id: 'ALT-1', details: 'café ✓' }]);
  assert.equal(blob.type, 'text/csv;charset=utf-8');
  const bytes = new Uint8Array(await blob.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 3)], [0xef, 0xbb, 0xbf]);
  const text = new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes);   // keep the BOM: the default decoder strips it
  assert.equal(text.charCodeAt(0), 0xfeff);
  assert.ok(text.includes('Zoë Ng') && text.includes('café ✓'));
});

// A fake browser. Each step can be made to fail, and every call is logged in order so the cleanup can be checked.
function fakeBrowser(opts = {}) {
  const { clickThrows = false, appendThrows = false, createElementThrows = false, removeThrows = false, createUrlThrows = false } = opts;
  const log = [];
  const timers = [];
  const link = {
    href: '',
    download: '',
    click() { log.push('click'); if (clickThrows) throw new Error('download blocked'); },
    remove() { log.push('remove'); if (removeThrows) throw new Error('remove failed'); },
  };
  const doc = {
    createElement(tag) { log.push(`create:${tag}`); if (createElementThrows) throw new Error('create failed'); return link; },
    body: { appendChild(el) { log.push('append'); if (appendThrows) throw new Error('append failed'); return el; } },
  };
  const env = {
    createUrl() { log.push('createUrl'); if (createUrlThrows) throw new Error('url failed'); return 'blob:fake-1'; },
    revokeUrl(url) { log.push(`revoke:${url}`); },
    doc,
    setTimer(fn, ms) { log.push(`timer:${ms}`); timers.push({ fn, ms }); },
  };
  return {
    env,
    link,
    log,
    timerCount: () => timers.length,
    fireTimers: () => timers.forEach((t) => t.fn()),
    revokes: () => log.filter((entry) => entry.startsWith('revoke')).length,
  };
}

test('the object URL is not revoked straight after the click, but after one timer', () => {
  const browser = fakeBrowser();
  const url = downloadBlob({}, 'socmind-audit-log-2026-11-10.csv', browser.env);
  assert.equal(url, 'blob:fake-1');
  assert.equal(browser.link.download, 'socmind-audit-log-2026-11-10.csv');
  assert.equal(browser.link.href, 'blob:fake-1');
  assert.deepEqual(browser.log, ['createUrl', 'create:a', 'append', 'click', 'remove', `timer:${REVOKE_DELAY_MS}`]);
  assert.equal(browser.revokes(), 0, 'revoked too early');
  browser.fireTimers();
  assert.equal(browser.log[browser.log.length - 1], 'revoke:blob:fake-1');
});

test('the revoke delay is short but not zero, and only one timer is started per download', () => {
  assert.ok(REVOKE_DELAY_MS >= 500 && REVOKE_DELAY_MS <= 5000);
  const browser = fakeBrowser();
  downloadBlob({}, 'x.csv', browser.env);
  assert.equal(browser.timerCount(), 1);
});

test('when the click throws, the link is removed, the URL is still scheduled once, and the error reaches the caller', () => {
  const browser = fakeBrowser({ clickThrows: true });
  assert.throws(() => downloadBlob({}, 'x.csv', browser.env), /download blocked/);
  assert.ok(browser.log.includes('remove'), 'the link must not stay in the page');
  assert.equal(browser.timerCount(), 1, 'exactly one revocation timer');
  assert.equal(browser.revokes(), 0);
  browser.fireTimers();
  assert.equal(browser.log[browser.log.length - 1], 'revoke:blob:fake-1');
});

test('when appendChild throws, the URL is still revoked after the delay, the anchor is removed, and the click never happens', () => {
  const browser = fakeBrowser({ appendThrows: true });
  assert.throws(() => downloadBlob({}, 'x.csv', browser.env), /append failed/);
  assert.equal(browser.log.includes('click'), false, 'the click must not run when the anchor was not attached');
  assert.ok(browser.log.includes('remove'), 'the created anchor is removed');
  assert.equal(browser.timerCount(), 1, 'the URL must still be scheduled for release');
  assert.equal(browser.revokes(), 0, 'not revoked before the delay');
  browser.fireTimers();
  assert.equal(browser.log[browser.log.length - 1], 'revoke:blob:fake-1');
  assert.equal(browser.revokes(), 1);
});

test('when createElement throws, the URL is still revoked once and no anchor is touched', () => {
  const browser = fakeBrowser({ createElementThrows: true });
  assert.throws(() => downloadBlob({}, 'x.csv', browser.env), /create failed/);
  assert.equal(browser.log.includes('remove'), false, 'there was no anchor to remove');
  assert.equal(browser.log.includes('append'), false);
  assert.equal(browser.timerCount(), 1);
  browser.fireTimers();
  assert.equal(browser.revokes(), 1);
});

test('when the URL cannot be created, nothing is scheduled and the error reaches the caller', () => {
  const browser = fakeBrowser({ createUrlThrows: true });
  assert.throws(() => downloadBlob({}, 'x.csv', browser.env), /url failed/);
  assert.equal(browser.timerCount(), 0, 'there is no URL to release');
  assert.deepEqual(browser.log, ['createUrl']);
});

test('when removing the anchor fails, the failure is ignored: the URL is still revoked once and the download is not reported as failed', () => {
  const browser = fakeBrowser({ removeThrows: true });
  assert.doesNotThrow(() => downloadBlob({}, 'x.csv', browser.env));
  assert.equal(browser.timerCount(), 1, 'the revocation must not be skipped because removal failed');
  browser.fireTimers();
  assert.equal(browser.revokes(), 1);
});

test('every failure path starts at most one revocation timer', () => {
  for (const opts of [{ clickThrows: true }, { appendThrows: true }, { createElementThrows: true }, { removeThrows: true }, {}]) {
    const browser = fakeBrowser(opts);
    try { downloadBlob({}, 'x.csv', browser.env); } catch { /* expected for the failing cases */ }
    assert.ok(browser.timerCount() <= 1, `timers for ${JSON.stringify(opts)}`);
  }
});

test('the export button is wired to the gated loader, the error state and the note (wiring guard)', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../pages/AuditLog.jsx', import.meta.url), 'utf8');
  assert.match(source, /from '\.\.\/lib\/auditCsv'/);
  assert.match(source, /from '\.\.\/lib\/auditLoad'/);
  assert.match(source, /Export CSV/);
  assert.match(source, /disabled=\{rows\.length === 0 \|\| loading \|\| Boolean\(error\)\}/);
  assert.match(source, /downloadBlob\(auditCsvBlob\(rows\), auditExportFilename\(\)\)/);
  assert.match(source, /auditExportNote\(rows\.length, hasMore, Boolean\(error\)\)/);
  assert.match(source, /createRequestGate/);
  assert.match(source, /receive\(gate, id, state/);
});

test('the export contains each audit id only once, keeping the first copy and the newest-first order', () => {
  const csv = auditRowsToCsv([
    { id: 3, timestamp: '2026-11-10T09:03:00', actor: 'A', action: 'X', target_id: 'T3', details: null },
    { id: 2, timestamp: '2026-11-10T09:02:00', actor: 'B', action: 'X', target_id: 'T2', details: null },
    { id: 3, timestamp: '2026-11-10T09:03:00', actor: 'A', action: 'X', target_id: 'T3', details: null },
    { id: 1, timestamp: '2026-11-10T09:01:00', actor: 'C', action: 'X', target_id: 'T1', details: null },
    { id: 2, timestamp: '2026-11-10T09:02:00', actor: 'B', action: 'X', target_id: 'T2', details: null },
  ]);
  const lines = csv.split('\r\n').filter(Boolean);
  assert.equal(lines.length, 4, 'header plus three distinct entries');
  assert.deepEqual(lines.slice(1).map((l) => l.split(',')[3]), ['T3', 'T2', 'T1']);
});

test('entries without an id are all exported, because they cannot be recognised as repeats', () => {
  const csv = auditRowsToCsv([{ actor: 'A', action: 'X' }, { actor: 'A', action: 'X' }]);
  assert.equal(csv.split('\r\n').filter(Boolean).length, 3);
});
