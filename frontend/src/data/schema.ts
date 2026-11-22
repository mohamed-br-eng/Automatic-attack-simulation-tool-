import { z } from 'zod'
export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
export const severitySchema = z.enum(severities)
const date = z.iso.datetime({ offset: true })
export const findingSchema = z.object({
  id: z.string().min(1),
  category: z.string().min(1),
  title: z.string().min(1),
  severity: severitySchema,
  evidence: z.string(),
  recommendation: z.string(),
  cvss_vector: z.string().default(''),
  cvss_score: z.number().min(0).max(10).default(0),
  epss: z.number().min(0).max(1).nullable().default(null),
  target: z.string().default(''),
  plugin: z.string().default(''),
  request: z.string().default(''),
  response: z.string().default(''),
  timestamp: date,
})
export const reportSchema = z
  .object({
    meta: z.object({
      target: z.string(),
      scan_id: z.string(),
      tool: z.string(),
      generated_at: date,
    }),
    summary: z.object({
      total: z.number().int().nonnegative(),
      by_severity: z.object({
        CRITICAL: z.number().int().nonnegative(),
        HIGH: z.number().int().nonnegative(),
        MEDIUM: z.number().int().nonnegative(),
        LOW: z.number().int().nonnegative(),
        INFO: z.number().int().nonnegative(),
      }),
      posture: severitySchema,
      top_risks: z.array(
        z.object({
          title: z.string(),
          severity: severitySchema,
          cvss_score: z.number().min(0).max(10),
          category: z.string(),
        }),
      ),
    }),
    findings: z.array(findingSchema).max(20000),
  })
  .superRefine((report, ctx) => {
    const ids = new Set<string>()
    for (const [index, f] of report.findings.entries()) {
      if (ids.has(f.id))
        ctx.addIssue({
          code: 'custom',
          path: ['findings', index, 'id'],
          message: 'Duplicate finding ID',
        })
      ids.add(f.id)
    }
    if (report.summary.total !== report.findings.length)
      ctx.addIssue({
        code: 'custom',
        path: ['summary', 'total'],
        message: 'Total does not match findings',
      })
    for (const severity of severities)
      if (
        report.summary.by_severity[severity] !==
        report.findings.filter((f) => f.severity === severity).length
      )
        ctx.addIssue({
          code: 'custom',
          path: ['summary', 'by_severity', severity],
          message: 'Severity count does not match findings',
        })
    const posture =
      severities.find((s) => report.findings.some((f) => f.severity === s)) ??
      'INFO'
    if (report.summary.posture !== posture)
      ctx.addIssue({
        code: 'custom',
        path: ['summary', 'posture'],
        message: 'Posture does not match findings',
      })
  })
export type Finding = z.infer<typeof findingSchema>
export type Report = z.infer<typeof reportSchema>
export type Severity = Finding['severity']
export const scanSchema = z.object({
  id: z.string().min(1),
  name: z.string(),
  target: z.string(),
  status: z.enum(['running', 'completed', 'failed', 'queued', 'snapshot']),
  progress: z.number().min(0).max(100).nullable(),
  startedAt: date.nullable(),
  finishedAt: date.nullable(),
  source: z.enum(['mock', 'p4', 'p3', 'api']),
  report: reportSchema,
  error: z.string().optional(),
})
export type Scan = z.infer<typeof scanSchema>
export const topologySchema = z.object({
  nodes: z.array(
    z.object({
      id: z.string(),
      label: z.string(),
      x: z.number(),
      y: z.number(),
    }),
  ),
  edges: z.array(
    z.object({ id: z.string(), source: z.string(), target: z.string() }),
  ),
})
export type Topology = z.infer<typeof topologySchema>
