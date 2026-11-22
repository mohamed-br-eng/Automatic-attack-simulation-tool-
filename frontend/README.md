# P5 · Sentinel dashboard

React + strict TypeScript + Vite dashboard for the existing Automatic Attacks Simulation Tool. All P5 changes are inside `frontend/`; shared Python contracts, reporting, scoring and attack plugins are unchanged. The planning documents are background material; this implementation follows the user's narrower frontend-only scope.

## Run locally

Use Node 22.12+ (tested with 22.16) and npm 10+. From `frontend/`:

```powershell
npm ci
npm run dev
```

Open the local address printed by Vite, normally <http://127.0.0.1:5173>. No Python service, database, AI account, or environment file is needed for demo mode. Dependencies must be installed once; runtime uses system fonts and no external assets.

```powershell
npm run build
npm run lint
npm test
npm run preview
```

`build` typechecks strict TypeScript and writes `dist/`. Deployments must serve `index.html` for unknown application routes so React Router deep links work. Build-time variables beginning with `VITE_` are public: never place secrets there.

## Features

- Responsive dark layout, mobile navigation, keyboard focus indicators, skip link, semantic tables and labeled form controls.
- Overview statistics, compact stacked severity bar and OWASP category chart (Recharts), priority review ordered by reported severity then CVSS.
- Scan history with status/progress, scan context, chronological timeline, and findings scoped to each scan.
- Searchable findings with severity, OWASP, target and data-source filters, including CVSS / EPSS sorting, with pagination and detail views for evidence, requests, responses, remediation, vector, score and EPSS.
- Local JSON import for P4 reports, Zod validation and actionable errors. Rejected imports do not alter existing results. HTML in evidence is rendered as inert text.
- P3 adapter with editable JSON mapping and nested field paths. This is provisional until P3 supplies its format.
- React Flow topology renderer when an API supplies nodes and edges; an explicit unavailable state otherwise. No invented network connections.
- AI assistant interface with disabled composer. LLM, RAG, AI prioritization and anomaly detection are marked unavailable. No fake AI messages or analysis.
- TanStack Query loading, retry, refresh and failure handling, plus separate mock/HTTP implementations of `DashboardApi`.

Demo mode has four static scan fixtures with explicit source labels. They do not launch scans or progress in real time. Overview totals include all loaded scans and imported snapshots; the same vulnerability in two scans counts twice. Imported snapshots remain labeled `p4` or `p3` and are distinguishable from demo results.

## Import P4 JSON

Choose **Report imports → P4 → Choose a JSON report**. A real fixture generated directly from the current `ReportBuilder` is committed at `src/test/fixtures/p4-report.json`; use it immediately or generate a report from the repository root:

```powershell
python -m reporting.demo
```

Then select `reports/demo.json`. This Python command needs the repository's dependencies; the frontend itself does not. Import is limited to 10 MB and 20,000 findings per file. Files are read in the browser, not uploaded or saved to localStorage. Imports are in memory and disappear on refresh. Each import receives a UI-local scan key; `meta.scan_id` and original finding IDs remain intact, including when separate reports contain the same finding ID.

The adapter accepts `meta`, `summary`, `findings` from `reporting/report.py`. It validates required contract fields, scores in 0–10, EPSS in 0–1 or null, offset-aware ISO timestamps, enum severities, unique IDs within a report, summary counts and posture. Optional Python fields get the dataclass defaults if absent. Unknown extension fields are ignored by Zod; they are not displayed. It does not parse or recalculate CVSS vectors: P4 currently accepts empty strings and the existing tests include a shortened example vector.

## P3 configuration

Choose P3 in the import form. Edit `itemsPath`, `fields`, and `severityMap`. Paths are dot-separated and read own object properties only. Required fields are `id`, `title`, `category`, `severity`, `evidence`, `recommendation`, and `timestamp`; map optional `target`, `plugin`, `request`, `response`, `cvss_vector`, `cvss_score`, `epss` if available. IDs and timestamps are never fabricated for findings. Unknown or invalid severities fail validation. No P3 schema has been assumed to be final.

The upload filename becomes the provisional report ID; report generation time is the import time, not a scan or finding timestamp. Missing target remains blank until supplied by finding data or the eventual backend.

## API integration

See [INTEGRATION.md](./INTEGRATION.md) for actual inspected contracts, missing fields and the P1 checklist. To select the prepared HTTP implementation, copy `.env.example` to `.env.local`, set `VITE_DATA_SOURCE=api`, set `VITE_API_BASE_URL`, and restart Vite. A backend failure is shown explicitly; it never silently switches to mock data. The HTTP implementation is an integration proposal and is not claimed to match an existing FastAPI service.

Only read operations are implemented. No scan launch, authorization gate, database access, AI endpoints or scoring changes are included. The existing `Context.ethics_gate` remains P1's responsibility. AI integration should supply a separate service abstraction with explicit capability availability, citations/provenance and reviewed outputs before enabling the composer.

## Source map

| Location                                  | Purpose                                                                     |
| ----------------------------------------- | --------------------------------------------------------------------------- |
| `src/data/schema.ts`                      | Frontend-owned Zod schemas and inferred types                               |
| `src/data/adapters.ts`                    | P4/P3 conversion and finding selection                                      |
| `src/data/api.ts`, `mock.ts`, `store.tsx` | Transport boundary, fixtures, query and import state                        |
| `src/pages/`                              | Overview, scan history/detail, findings/detail, reports, assistant, network |
| `src/components/`                         | Reusable states, findings table, shadcn-style source components             |
| `src/test/`                               | Adapter/API and user workflow tests, real P4 export fixture                 |
| `src/styles.css`                          | Tailwind v4 entry, theme and responsive layout                              |

Button and Input are locally owned shadcn/ui source components using Radix Slot, CVA, clsx and tailwind-merge; `components.json` and the `@/` alias support further shadcn additions. Upstream attribution is in `THIRD_PARTY_NOTICES.md`. Setup references: [Vite](https://vite.dev/guide/), [Tailwind Vite integration](https://tailwindcss.com/docs/installation/using-vite), [shadcn Button](https://ui.shadcn.com/docs/components/radix/button).

Git workflow: local feature branch `p5/dashboard`. No push, PR, merge, or remote write is authorized by this document.

## Verification performed

Validated locally on 22 November 2026:

- `npm run build`: passed, including strict TypeScript. Rollup emitted two upstream Zod comment-annotation warnings; output was generated successfully.
- `npm run lint`: passed with zero errors and zero warnings.
- `npm test`: 34 tests passed (22 adapter/API cases, 12 dashboard workflows). Includes actual P4 export compatibility, invalid reports, nested P3 mappings, filtering/sorting, import recovery, inert HTML evidence, disabled AI, API errors mobile keyboard navigation, source-scoped chart consistency, target filters and pagination.
- From repository root, `frontend/.venv/Scripts/python.exe -m pytest -q`: all 23 existing Python tests passed. This ignored local virtual environment contains only test dependencies; no Python source or dependency files were changed.
- Browser review at desktop and 390 × 844 mobile dimensions: checked overview, charts, mobile menu, and page width. Fixed overflow from hidden table headings and mobile chart sizing. Desktop viewport restored afterward.
- `git diff --exit-code HEAD -- core plugins reporting scoring tests requirements.txt pytest.ini`: passed, confirming teammates' tracked source and tests are unchanged.

Current limitations: imported history is in memory; API paths remain a documented proposal; demo progress is static; topology and AI remain unavailable without their services.

## Analyst workstation redesign

The overview now puts priority findings above compact charts and operational metrics. The charcoal / teal visual system is shared by all routes, with compact headers, an understated sidebar, 4px radii and monospace technical fields. Finding tables show severity, vulnerability, target, CVSS, EPSS, plugin plus data provenance, and observation time. The overview source selector scopes metrics, charts, priority findings and recent scans to the same loaded reports.

See [REDESIGN.md](./REDESIGN.md) for the audit, exact changed-file list and validation. The existing Finding schema has no CWE field, so a CWE filter is not exposed. No missing vulnerability metadata is fabricated.
