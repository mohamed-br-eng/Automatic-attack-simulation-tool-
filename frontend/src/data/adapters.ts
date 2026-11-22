import { z } from 'zod'
import {
  findingSchema,
  reportSchema,
  severities,
  type Finding,
  type Report,
  type Scan,
} from './schema'
export function makeReport(findings: Finding[], meta: Report['meta']): Report {
  const by_severity = Object.fromEntries(
    severities.map((s) => [s, findings.filter((f) => f.severity === s).length]),
  ) as Report['summary']['by_severity']
  return reportSchema.parse({
    meta,
    findings,
    summary: {
      total: findings.length,
      by_severity,
      posture: severities.find((s) => by_severity[s]) ?? 'INFO',
      top_risks: [...findings]
        .filter((f) => ['CRITICAL', 'HIGH'].includes(f.severity))
        .sort(
          (a, b) =>
            severities.indexOf(a.severity) - severities.indexOf(b.severity) ||
            b.cvss_score - a.cvss_score,
        )
        .slice(0, 5),
    },
  })
}
export function fromP4(input: unknown): Scan {
  const report = reportSchema.parse(input)
  // generated_at is a report time, never an invented scan start/end time.
  return {
    id: report.meta.scan_id || `report-${crypto.randomUUID()}`,
    name: report.meta.scan_id || 'Imported report',
    target: report.meta.target,
    status: 'snapshot',
    progress: null,
    startedAt: null,
    finishedAt: null,
    source: 'p4',
    report,
  }
}
export interface P3AdapterConfig {
  itemsPath: string
  fields: Record<
    | 'id'
    | 'title'
    | 'category'
    | 'severity'
    | 'evidence'
    | 'recommendation'
    | 'timestamp',
    string
  > &
    Partial<Record<keyof Finding, string>>
  severityMap: Record<string, Finding['severity']>
}
export const defaultP3Config: P3AdapterConfig = {
  itemsPath: 'results',
  fields: {
    id: 'id',
    title: 'title',
    category: 'category',
    severity: 'severity',
    evidence: 'evidence',
    recommendation: 'recommendation',
    timestamp: 'timestamp',
    target: 'target',
    plugin: 'plugin',
    cvss_score: 'cvss_score',
    cvss_vector: 'cvss_vector',
    epss: 'epss',
    request: 'request',
    response: 'response',
  },
  severityMap: {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
    info: 'INFO',
    informational: 'INFO',
  },
}
export function atPath(input: unknown, path: string): unknown {
  return path
    .split('.')
    .filter(Boolean)
    .reduce<unknown>(
      (value, key) =>
        value !== null && typeof value === 'object' && Object.hasOwn(value, key)
          ? (value as Record<string, unknown>)[key]
          : undefined,
      input,
    )
}
export function fromP3(
  input: unknown,
  config: P3AdapterConfig,
  meta: Report['meta'],
): Scan {
  const items = z
    .array(z.unknown())
    .max(20000)
    .parse(atPath(input, config.itemsPath))
  const findings = items.map((item) => {
    const mapped: Record<string, unknown> = Object.fromEntries(
      Object.entries(config.fields).map(([key, path]) => [
        key,
        atPath(item, path),
      ]),
    )
    if (typeof mapped.severity === 'string')
      mapped.severity =
        config.severityMap[mapped.severity.toLowerCase()] ?? mapped.severity
    return findingSchema.parse(mapped)
  })
  return { ...fromP4(makeReport(findings, meta)), source: 'p3' }
}
export function parseP3Config(text: string): P3AdapterConfig {
  const paths = z.string().min(1)
  return z
    .object({
      itemsPath: z.string(),
      fields: z
        .object({
          id: paths,
          title: paths,
          category: paths,
          severity: paths,
          evidence: paths,
          recommendation: paths,
          timestamp: paths,
        })
        .catchall(paths),
      severityMap: z.record(z.string(), z.enum(severities)),
    })
    .parse(JSON.parse(text))
}
export function selectFindings(
  findings: Finding[],
  search: string,
  severity: string,
  category: string,
  sort: string,
) {
  const query = search.toLowerCase()
  return findings
    .filter(
      (f) =>
        `${f.title} ${f.target} ${f.plugin} ${f.id}`
          .toLowerCase()
          .includes(query) &&
        (severity === 'all' || f.severity === severity) &&
        (category === 'all' || f.category === category),
    )
    .sort((a, b) =>
      sort === 'newest'
        ? Date.parse(b.timestamp) - Date.parse(a.timestamp)
        : sort === 'epss'
          ? (b.epss ?? -1) - (a.epss ?? -1)
          : sort === 'title'
            ? a.title.localeCompare(b.title)
            : sort === 'score'
              ? b.cvss_score - a.cvss_score
              : severities.indexOf(a.severity) -
                  severities.indexOf(b.severity) || b.cvss_score - a.cvss_score,
    )
}
