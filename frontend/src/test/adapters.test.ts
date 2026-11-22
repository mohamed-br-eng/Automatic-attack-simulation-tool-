import { describe, expect, it } from 'vitest'
import {
  defaultP3Config,
  fromP3,
  fromP4,
  makeReport,
  parseP3Config,
  selectFindings,
} from '@/data/adapters'
import { mockScans } from '@/data/mock'
import { createHttpApi } from '@/data/api'
import p4Fixture from './fixtures/p4-report.json'
const report = mockScans()[0].report
describe('P4 contract', () => {
  it('imports an actual ReportBuilder export from the existing Python source', () => {
    const scan = fromP4(p4Fixture)
    expect(scan.report.findings).toHaveLength(3)
    expect(scan.report.findings[0].title).toBe(
      'Identifiants faibles valides : admin:password',
    )
    expect(scan.report.findings[1].epss).toBe(0.08)
  })
  it('preserves serialized Finding fields without inventing lifecycle metadata', () => {
    const scan = fromP4(JSON.parse(JSON.stringify(report)))
    expect(scan.report).toEqual(report)
    expect(scan.status).toBe('snapshot')
    expect(scan.startedAt).toBeNull()
    expect(scan.progress).toBeNull()
  })
  it('accepts empty P4 reports and empty scan IDs', () => {
    const scan = fromP4(makeReport([], { ...report.meta, scan_id: '' }))
    expect(scan.id).toMatch(/^report-/)
    expect(scan.report.summary.posture).toBe('INFO')
  })
  it.each([
    [
      'bad severity',
      (r: typeof report) => {
        r.findings[0].severity = 'urgent' as never
      },
    ],
    [
      'invalid score',
      (r: typeof report) => {
        r.findings[0].cvss_score = 11
      },
    ],
    [
      'invalid EPSS',
      (r: typeof report) => {
        r.findings[0].epss = -0.1
      },
    ],
    [
      'bad timestamp',
      (r: typeof report) => {
        r.findings[0].timestamp = 'yesterday'
      },
    ],
    [
      'duplicate IDs',
      (r: typeof report) => {
        r.findings[1].id = r.findings[0].id
      },
    ],
    [
      'wrong total',
      (r: typeof report) => {
        r.summary.total = 99
      },
    ],
    [
      'wrong counts',
      (r: typeof report) => {
        r.summary.by_severity.HIGH = 99
      },
    ],
    [
      'wrong posture',
      (r: typeof report) => {
        r.summary.posture = 'INFO'
      },
    ],
  ])('rejects %s', (_, mutate) => {
    const r = structuredClone(report)
    mutate(r)
    expect(() => fromP4(r)).toThrow()
  })
})
describe('configurable P3 adapter', () => {
  it('maps nested paths and custom severity labels', () => {
    const config = {
      ...defaultP3Config,
      itemsPath: 'data.issues',
      fields: {
        ...defaultP3Config.fields,
        title: 'details.name',
        severity: 'level',
      },
      severityMap: { urgent: 'CRITICAL' as const },
    }
    const scan = fromP3(
      {
        data: {
          issues: [
            {
              ...report.findings[0],
              details: { name: 'Nested finding' },
              level: 'urgent',
            },
          ],
        },
      },
      config,
      report.meta,
    )
    expect(scan.source).toBe('p3')
    expect(scan.report.findings[0].title).toBe('Nested finding')
    expect(scan.report.findings[0].severity).toBe('CRITICAL')
  })
  it('requires source evidence, IDs and timestamps', () => {
    expect(() =>
      fromP3(
        { results: [{ title: 'Incomplete' }] },
        defaultP3Config,
        report.meta,
      ),
    ).toThrow()
  })
  it('validates mapping configuration', () => {
    expect(parseP3Config(JSON.stringify(defaultP3Config))).toEqual(
      defaultP3Config,
    )
    expect(() => parseP3Config('{}')).toThrow()
  })
})
describe('finding selection', () => {
  it('sorts known EPSS values ahead of missing values, including a real zero', () => {
    const source = report.findings
      .slice(0, 3)
      .map((f, i) => ({ ...f, epss: [null, 0, 0.9][i] }))
    expect(
      selectFindings(source, '', 'all', 'all', 'epss').map((f) => f.epss),
    ).toEqual([0.9, 0, null])
  })
  it('combines search, severity and category filters', () => {
    expect(
      selectFindings(
        report.findings,
        'weak',
        'HIGH',
        'A07:2025 Authentication Failures',
        'score',
      ),
    ).toHaveLength(1)
  })
  it('sorts highest severity first and supports score/title/date sorts', () => {
    expect(
      selectFindings(
        [...report.findings].reverse(),
        '',
        'all',
        'all',
        'severity',
      )[0].severity,
    ).toBe('CRITICAL')
    expect(
      selectFindings(report.findings, '', 'all', 'all', 'score')[0].cvss_score,
    ).toBe(9.4)
    expect(
      selectFindings(report.findings, '', 'all', 'all', 'title')[0].title,
    ).toBe('Missing content security policy')
    expect(
      selectFindings(report.findings, '', 'all', 'all', 'newest')[0].severity,
    ).toBe('INFO')
  })
})
describe('HTTP API boundary', () => {
  it('validates backend scan data', async () => {
    const api = createHttpApi(
      'http://localhost/api/',
      async () => new Response(JSON.stringify(mockScans())),
    )
    expect(await api.listScans()).toHaveLength(4)
  })
  it('reports HTTP failures without silently falling back to demo data', async () => {
    const api = createHttpApi(
      '/api',
      async () => new Response('', { status: 503 }),
    )
    await expect(api.listScans()).rejects.toThrow('503')
  })
  it('rejects incompatible backend payloads', async () => {
    const api = createHttpApi('/api', async () => new Response('{}'))
    await expect(api.listScans()).rejects.toThrow()
  })
  it('treats an unimplemented topology endpoint as unavailable', async () => {
    const api = createHttpApi(
      '/api',
      async () => new Response('', { status: 404 }),
    )
    expect(await api.getTopology()).toBeNull()
  })
  it('validates available topology', async () => {
    const topology = {
      nodes: [{ id: 'lab', label: 'Local lab', x: 0, y: 0 }],
      edges: [],
    }
    const api = createHttpApi(
      '/api',
      async () => new Response(JSON.stringify(topology)),
    )
    expect(await api.getTopology()).toEqual(topology)
  })
})
