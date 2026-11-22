# P5 integration notes

## Inspected source contracts

| Source                     | Reusable contract / implication                                                                                                                                                                                                                                   |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `core/finding.py`          | Provisional P4 proposal awaiting P1 approval. Required category, title, severity, evidence, recommendation; default vector, score, EPSS, target, plugin, request, response, UUID ID, UTC timestamp. `to_dict()` emits enum values and ISO timestamps. Unmodified. |
| `core/plugin.py`           | `AttackPlugin.run(Target, Context) -> list[Finding]`; registry identifies plugin names. Frontend displays plugin strings; it never executes plugins.                                                                                                              |
| `core/context.py`          | Target host/base URL/port and authorization/private-address ethics gate. The backend must enforce it; no browser authorization bypass or scan launch is implemented.                                                                                              |
| `reporting/report.py`      | `meta: {target, scan_id, tool, generated_at}`; `summary: {total, by_severity, posture, top_risks}`; `findings: Finding.to_dict()[]`. Findings sorted severity then descending CVSS. JSON is P4's source of truth.                                                 |
| `scoring/cvss4.py`         | Current implementation explicitly documents an approximation rather than official FIRST MacroVector scoring. Dashboard labels scores as reported and does not recalculate. `risk_priority` is also P4-owned and is not reimplemented here.                        |
| Existing tests / P4 README | P4 reporting empty reports and defaults, severity ordering, shortened vector examples, EPSS handling, plugins and provisional shared ownership. A fixture was generated with the actual unmodified `ReportBuilder` and demo findings.                             |

## Missing fields / compatibility decisions

- No backend/API implementation exists in this checkout. No endpoint, authentication policy, pagination, event schema or CORS policy is established.
- No scan start/end, status, progress, lifecycle events, selected plugins or failure reason in P4 JSON. Imported reports use `snapshot`, null progress/start/end. `generated_at` is shown only as report generation time. Timelines use observed finding timestamps and report generation without inventing attack events.
- No topology, ports, service banners or network edges. P4 findings alone cannot establish connections. React Flow stays unavailable until supplied with real topology.
- No schema version. Adapters are isolated so P1's approved Finding/API contract can replace the provisional one without modifying Python modules. Enum values are uppercase; optional dataclass defaults are supported. Required evidence and timestamps are not guessed.
- OWASP strings are producer-supplied and displayed verbatim, grouped by exact category. P5 does not correct or reinterpret teammates' categories.
- No CVE/CWE identifiers, exposure, finding status, deduplication key, model confidence, citations, anomaly scores or AI output fields. These need approved enrichment contracts; no fields are added to Finding.
- Summary validation rejects mismatched totals, severity counts or posture. `top_risks` entries are shape-validated; the priority review derives from findings to avoid trusting arbitrary ordering. Blank scan IDs get local UUID keys; duplicate finding IDs within one report are rejected. Separate scans may share IDs safely.
- Snapshot imports are browser-memory only. Persistent history needs P1's authorized storage/API. Demo progress is static and explicitly labeled.

## Proposed read-only HTTP boundary

`DashboardApi` has `listScans(signal?)` and `getTopology(signal?)`. Query cancellation passes AbortSignal through fetch. HTTP errors or schema errors are visible; one retry is allowed. The API is opt-in via build-time environment configuration. No direct database access.

The current HTTP adapter proposes `GET {base}/scans` returning an array matching frontend `scanSchema`:

```typescript
{
  id: string, name: string, target: string,
  status: 'running' | 'completed' | 'failed' | 'queued' | 'snapshot',
  progress: number | null, // 0–100
  startedAt: string | null, finishedAt: string | null, // ISO + timezone
  source: 'api',
  report: { meta, summary, findings }, // exact P4-compatible body
  error?: string
}[]
```

This is a frontend transport proposal, not a change to the shared Finding contract. If P1 uses separate scan and report endpoints, implement the join inside `createHttpApi` and preserve the UI-facing abstraction. The prototype currently loads full reports for all scans; server pagination and individual report fetching are needed for large deployments.

Optional `GET {base}/topology`:

```json
{
  "nodes": [{ "id": "lab", "label": "Lab target", "x": 0, "y": 0 }],
  "edges": []
}
```

404/204 mean capability unavailable. Other HTTP errors are displayed. No topology is synthesized from finding URLs. UI currently consumes global topology; agree scan scoping before production use.

## Information needed from P1 (and P2/P3)

1. Approved Finding schema/version, nullable/optional field rules, stable IDs and timestamp conventions.
2. FastAPI base URL/OpenAPI spec; actual list/detail/report paths and response envelopes; filters/pagination and error format.
3. Authentication/session requirements, CORS origin policy for the Vite address, credential handling and CSRF policy. Do not put API secrets in Vite environment variables. Fetch currently sends no bearer token and no cross-origin cookies.
4. Scan lifecycle states, progress semantics, start/end timestamps, event IDs and ordering; future WebSocket/SSE URL/auth/reconnect/backfill protocol. No live subscription is implemented yet.
5. Authorization/scope contract for any future scan-start action. Launch controls should be added only after P1's ethics gate and API are agreed.
6. P1/P2 topology payload, node/edge identifiers, ports/services, scan association and capability discovery. P3's actual report example and field mapping.
7. Retention/redaction rules for potentially sensitive raw requests/responses, history persistence and deduplication across scans.

## Deferred intelligence

No LLM, RAG or Isolation Forest code exists in this change. Future AI data should be separate enrichments keyed by stable scan/finding IDs, with capability flags, model/version, provenance, citations and review status. Existing findings stay the source evidence; the UI must not display invented analysis while those services are absent.
