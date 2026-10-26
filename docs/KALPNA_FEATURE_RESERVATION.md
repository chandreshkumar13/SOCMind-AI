# Reserved feature for Kalpna Chaudhary: Incident list search, filtering and sorting

**Status: reserved and NOT implemented.** Nothing for this feature has been started on any branch. The rest of the
application is complete and does not depend on it.

## Why this feature, and why it is a good independent task

An analyst working a busy queue needs to find incidents quickly: "show me CRITICAL incidents that are still waiting
for a decision", or "everything on FINANCE-WKS-042". The Alerts page already has severity buttons and a text search.
The Audit Log page has filters. **The Correlated Incidents page has none**: it lists every incident in the order the
API returns them.

It was chosen because it is:

- **Missing today.** Checked in `frontend/src/pages/Incidents.jsx`: the only filtering is hiding `MERGED`
  incidents (the `visible` and `pending` constants inside the `Incidents` component). There is no search box, no filter
  control and no sort control. No other file filters incidents.
- **Almost entirely frontend.** It can be done on the incidents the page already receives. No backend change is needed.
- **Easy to test on its own.** The filtering rules are pure functions, and this repository already tests such
  functions with Node's built-in test runner (`frontend/src/lib/view.test.js`).
- **Genuinely useful to a SOC analyst** and easy to review in a pull request.

## Scope

Add a filter bar above the incident cards in the Incidents page with:

1. **Text search** (case-insensitive) over: incident id, title, AI summary, and the hosts, users and IPs found in the
   investigation entities (`details.investigation.entities`) when present.
2. **Severity filter**: ALL, CRITICAL, HIGH, MEDIUM, LOW, INFO (same visual style as the Alerts page buttons).
3. **Approval filter**: ALL, PENDING, APPROVED, REJECTED (field `human_approval_status`).
4. **Workflow status filter**: ALL, OPEN, INVESTIGATED, RESPONSE_PROPOSED, RESPONSE_APPROVED, RESPONSE_REJECTED,
   RESPONSE_SIMULATED (field `status`).
5. **Sort**: newest first (default, `created_at`), oldest first, highest severity first, most alerts first
   (`correlated_alert_ids.length`).
6. A line such as "Showing 3 of 12 incidents" and a "Clear filters" control.
7. A clear empty state when filters match nothing (different from the existing "No incidents yet" state).

Filtering and sorting are applied **client-side** to the incident list the page already receives.

### Out of scope (do not do these)

- Backend or API changes, new endpoints, or new database columns.
- Changing the incident detail view, the investigation, recommendations, approval or simulation components.
- Server-side pagination, saved filters, or persisting filters between visits.
- Any change to the Alerts, Audit Log, Dashboard or Settings pages.

## Acceptance criteria

1. Typing in the search box immediately narrows the list; matching is case-insensitive and ignores leading and
   trailing spaces. Searching `finance-wks` finds the incident whose host is `FINANCE-WKS-042`.
2. Each filter works alone and in combination (all active filters must match: AND).
3. Sorting works for all four options and is stable: equal values keep a deterministic order (fall back to incident id).
4. Severity sorting uses the order CRITICAL > HIGH > MEDIUM > LOW > INFO. Unknown values sort last.
5. The "Showing X of Y" line counts only incidents that are not `MERGED`.
6. "Clear filters" restores the default view.
7. With zero incidents the existing "No incidents yet" message still appears. With incidents but no matches, a
   different "No incidents match the current filters" message appears.
8. Expanding an incident, approving, rejecting, simulating and re-running the pipeline still work exactly as before,
   and filter selections are not lost when the list refreshes after one of these actions.
9. The filtering and sorting rules live in a pure, exported function (suggested: `filterAndSortIncidents(incidents,
   criteria)` in a new file `frontend/src/lib/incidentFilters.js`) with unit tests.
10. `npm test`, `npm run build` and `npm run test:integration` all pass.

## Files to inspect first

| File | Why |
| --- | --- |
| `frontend/src/pages/Incidents.jsx` | The page to change. The list is rendered at the bottom of the default export (`visible.map(...)`). |
| `frontend/src/pages/Alerts.jsx` | Existing filter bar and search box: copy its look and behaviour (severity buttons, search input styling). |
| `frontend/src/pages/AuditLog.jsx` | A second example of a filter form in this codebase. |
| `frontend/src/lib/view.js` and `view.test.js` | Where small pure helpers and their tests live. |
| `frontend/src/components/StatusBadge.jsx` and `frontend/src/index.css` | Existing styling to reuse (do not add a UI library). |

## Files and areas that should NOT be modified unnecessarily

- Everything under `backend/`.
- `frontend/src/api.js` and `frontend/src/lib/useAsync.js`.
- `frontend/src/App.jsx` (it already passes the incident list down; no change should be needed).
- The detail components exported from `Incidents.jsx` (`Correlation`, `CorrelatedAlerts`, `Investigation`,
  `Recommendations`, `Review`, `Simulation`, `ReviewHistory`): the integration test renders them directly.
- `frontend/scripts/integration-smoke.mjs`, except to **add** checks for the new filter bar.

## API contract to reuse (no change)

`GET /api/v1/incidents?limit=100` returns a list of incidents (this is what `App.jsx` already loads):

```json
{
  "id": "INC-2026-001",
  "created_at": "2026-10-22T14:18:05.601364Z",
  "title": "Outbound Connection to Known Malicious C2 IP (+2 related alerts) on FINANCE-WKS-042",
  "severity": "CRITICAL",
  "status": "RESPONSE_PROPOSED",
  "correlated_alert_ids": ["ALT-2026-001", "ALT-2026-004", "ALT-2026-010"],
  "ai_summary": "Incident INC-2026-001 groups 3 alert(s) on FINANCE-WKS-042 ...",
  "recommended_action": "Block outbound traffic to 185.220.101.5 at the perimeter firewall",
  "human_approval_status": "PENDING",
  "details": { "investigation": { "entities": { "hosts": [], "users": [], "ips": [] } } }
}
```

The backend also accepts `severity`, `status` and `approval` query parameters on this endpoint. They are **not** needed
for this task (the list is filtered in the browser) and the API returns at most 100 incidents per request.

## Suggested branch

```bash
git switch main && git pull
git switch -c feature/incident-list-filters
```

Open a pull request into `main` when done. Do not combine it with other changes.

## Test plan

1. **Unit tests** (`npm test`): add `frontend/src/lib/incidentFilters.test.js` covering search (case, spaces, host and
   user from `details`), each filter, combined filters, all four sort orders, stable ordering on ties, unknown
   severity, an empty list, and `MERGED` incidents being excluded.
2. **Integration test** (`npm run test:integration`): add checks that render the Incidents page with live data and
   confirm the filter bar and the "Showing X of Y" line appear. This test starts the real backend on a temporary
   database; it needs Python with `backend/requirements.txt` installed.
3. **Build** (`npm run build`) succeeds.
4. **Manual check** (backend on port 8000, `npm run dev`): load sample alerts, run the full pipeline, then open
   *Correlated Incidents*. Try each filter and sort, combine them, clear them, then approve an incident and confirm
   the filters are still applied.

## Confirmation

As of the day this document was written, **none of the above is implemented**: `Incidents.jsx` contains no search
input, no filter controls and no sort control, and `frontend/src/lib/incidentFilters.js` does not exist.
