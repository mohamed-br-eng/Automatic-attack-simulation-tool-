# SENTINEL · analyst workstation redesign

Implemented locally on `p5/dashboard`, 22 November 2026. This refactors the existing P5 frontend; no P1–P4 modules or shared contracts changed, and no dependencies were added.

## Audit and changes

| Existing issue                                                       | Implemented change                                                                                                       |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Large heading, repeated eyebrow and descriptive copy delayed results | Compact Overview heading and inline report import / source controls                                                      |
| Four large decorative KPI cards                                      | One compact operational metrics strip with contextual counts                                                             |
| Priority findings appeared below two large charts                    | Priority review is the first data panel, above charts                                                                    |
| Large doughnut / sparse category chart                               | Stacked severity bar with counts and percentages, compact horizontal OWASP bars                                          |
| Five-column findings table hid investigation context                 | Severity-first table with vulnerability, target, CVSS, EPSS, detection plugin, data provenance and observation timestamp |
| No exact target or provenance filters                                | Combined target/source/severity/OWASP/search filters, result count, reset and pagination                                 |
| No EPSS sort                                                         | Descending EPSS, with unknown values after known values including zero                                                   |
| Repeated workspace card and generous navigation spacing              | Understated compact sidebar retaining every route and accessible mobile dialog                                           |
| Different page visual weights                                        | Shared charcoal surfaces, teal actions, 4px radii, compact headers, typography, table and form dimensions                |

The overview source selector scopes metrics, priority findings, severity distribution, OWASP counts and recent scans to the same dataset. Priority review shows the first five findings from that dataset; its caption states the limit. A finding in multiple scan snapshots remains multiple observations. Sources are labeled Demo, P3 import, P4 import or API at row level. No synthetic CWE field/filter, network relationships, progress updates or AI analysis were added.

## Files changed for this redesign

All paths below are relative to `frontend/`:

- `src/App.tsx`: sidebar, compact demo notice and unavailable assistant navigation label.
- `src/styles.css`: consistent visual system, density, responsive layout, scrollable tables and accessible focus styles.
- `src/components/findings-table.tsx`: seven-column investigation table, target/source filters, sorting, reset, source labels and pagination.
- `src/components/ui/button.tsx`, `src/components/ui/input.tsx`: shared control sizing and neutral/teal styling.
- `src/lib/provenance.ts` (new): source labels and source matching shared by overview and findings.
- `src/data/adapters.ts`: EPSS selection sort only; P3/P4 parsing and validation remain unchanged.
- `src/pages/overview.tsx`: findings-first hierarchy, source scope, compact metrics and charts.
- `src/pages/findings.tsx`, `src/pages/scans.tsx`: provenance, denser context and retained details/timeline.
- `src/pages/network.tsx`, `src/pages/reports.tsx`, `src/pages/assistant.tsx`: consistent compact pages and explicit capability states.
- `src/test/dashboard.test.tsx`, `src/test/adapters.test.ts`: regression coverage for overview source consistency, target/source filters, reset, pagination and EPSS ordering.
- `README.md`, `REDESIGN.md` (new): current behavior, audit and verification notes.
- `docs/redesign-overview.jpg` (new): browser preview of the revised overview.

## Preserved behavior

React Router paths, TanStack Query loading/error/retry behavior, mock and prepared HTTP implementations, P4 JSON import, configurable P3 mapping, validation and import error recovery, in-memory reports, scan history/status/progress, finding links scoped to scans, evidence rendered as inert text, HTTP request/response inspection, remediation, CVSS/EPSS values, timeline, conditional React Flow rendering, disabled AI composer, mobile focus trapping and Escape dismissal.

## Verification

- Strict TypeScript and Vite production build passed.
- ESLint passed with no errors or warnings.
- Vitest: 34 tests passed (22 adapter/API, 12 dashboard workflows).
- Existing Python regression suite: 23 tests passed using the ignored frontend-local virtual environment.
- Browser review: desktop overview, findings, target filtering, scans, network unavailable state, report import form, assistant placeholder; 390 × 844 mobile overview/findings/navigation with no document-level horizontal overflow. Tables scroll independently and support keyboard focus. Temporary viewport override restored.
- P4 parsing and import workflows pass automated tests, including a real export from the existing Python ReportBuilder. Browser-automated file selection was restricted by the Edge extension's file-access setting; no browser permission settings were changed.
- No dependency/package changes; shared Python modules and tests remain unchanged.

## Remaining limits

Imports remain in browser memory; refreshing clears them. CWE metadata is absent from the current contract. API paths and lifecycle/network payloads still require P1 approval. Network and AI features require their actual data/services. Build output retains two existing upstream Zod comment-annotation warnings; these do not prevent the build.

No commit, push, pull request, merge, remote write or remote history change was performed.
