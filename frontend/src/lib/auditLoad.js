// Pure state rules for the Audit Log list (no React). The page keeps one state object and applies these functions to it.
//
// Requests are numbered. Only the newest request may change the list or the loading flag, so a response that arrives late,
// from an older filter or an older page, is ignored instead of overwriting newer results.
//
// The server orders audit entries newest first by id and pages them with an offset. Entries inserted while the user is paging
// move the older entries down, so a page can repeat an entry that was already loaded. The list therefore keeps one copy of
// each id, and "Load older" asks the server for the offset it has actually reached (nextOffset), not for the number of rows
// shown, which can be smaller after de-duplication.

/** Removes repeated entries with the same id, keeping the first copy, so the original order is kept. Entries without an id are never merged. */
export function uniqueById(entries) {
  const seen = new Set();
  const out = [];
  for (const entry of entries || []) {
    const id = entry ? entry.id : undefined;
    if (id !== undefined && id !== null) {
      if (seen.has(id)) continue;
      seen.add(id);
    }
    out.push(entry);
  }
  return out;
}

/** Numbers requests. start() returns the number of a new request; isCurrent(id) is true only for the newest one. */
export function createRequestGate() {
  let latest = 0;
  return {
    start() {
      latest += 1;
      return latest;
    },
    isCurrent(id) {
      return id === latest;
    },
  };
}

/**
 * The initial list: nothing loaded yet, no error, and the server offset at 0. Loading starts as true because the first request
 * is about to be sent. Starting it as false would make the first render show "No audit entries match" before any data exists.
 */
export function initialList() {
  return { rows: [], hasMore: false, error: null, loading: true, nextOffset: 0 };
}

/** A request has started: the flag is set and the previous error is cleared. Rows are kept until the answer arrives. */
export function beginRequest(state) {
  return { ...state, loading: true, error: null };
}

/**
 * A page arrived. The first page (offset 0) replaces the rows; a later page is appended. Repeated ids are dropped. nextOffset
 * moves by the number of entries the server returned, duplicates included, because that is where the server's paging is.
 */
export function pageLoaded(state, offset, page, pageSize) {
  const rows = offset === 0 ? uniqueById(page) : uniqueById([...state.rows, ...page]);
  return {
    rows,
    hasMore: page.length === pageSize,
    error: null,
    loading: false,
    nextOffset: offset + page.length,
  };
}

/**
 * A request failed. A failed first page (offset 0) clears the rows: they belong to the previous filter, so they must not be
 * shown or exported as results for the filters that were just applied. A failed later page keeps the rows, which still belong
 * to the applied filter, and the error stays visible.
 */
export function pageFailed(state, offset, message) {
  if (offset === 0) return { rows: [], hasMore: false, error: message, loading: false, nextOffset: 0 };
  return { rows: state.rows, hasMore: state.hasMore, error: message, loading: false, nextOffset: state.nextOffset };
}

/**
 * Applies the answer to request `id`. If a newer request has started since, the answer is ignored completely, so neither its
 * rows, its error nor its loading flag can touch the newer request.
 */
export function receive(gate, id, state, outcome, pageSize) {
  if (!gate.isCurrent(id)) return state;
  if (outcome.error !== undefined) return pageFailed(state, outcome.offset, outcome.error);
  return pageLoaded(state, outcome.offset, outcome.page, pageSize);
}
