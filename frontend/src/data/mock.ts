import { findingSchema, type Scan } from './schema'
import { makeReport } from './adapters'
const specs = [
  [
    'SQL injection in product search',
    'CRITICAL',
    9.4,
    'A05:2025 Injection',
    'sqli',
    '/rest/products/search',
    'A controlled boolean probe returned different results for true and false conditions.',
    'Use parameterized queries and validate input types.',
  ],
  [
    'Weak credentials accepted',
    'HIGH',
    8.7,
    'A07:2025 Authentication Failures',
    'bruteforce',
    '/login',
    'Demo evidence: a test account accepted a weak password.',
    'Require strong passwords, MFA, and rate limiting.',
  ],
  [
    'Object accessible without ownership check',
    'HIGH',
    8.1,
    'A01:2025 Broken Access Control',
    'access_control',
    '/api/users/2',
    'Demo evidence: another test user record was returned.',
    'Enforce server-side ownership checks on each request.',
  ],
  [
    'Reflected input in HTML response',
    'MEDIUM',
    6.4,
    'A05:2025 Injection',
    'xss',
    '/search',
    'A harmless canary was reflected in an HTML context.',
    'Encode output for its destination context and enforce a CSP.',
  ],
  [
    'Missing content security policy',
    'LOW',
    3.1,
    'A02:2025 Security Misconfiguration',
    'headers',
    '/',
    'Content-Security-Policy header was absent in the demo response.',
    'Define a restrictive Content-Security-Policy and test in report-only mode.',
  ],
  [
    'Server technology disclosed',
    'INFO',
    0,
    'A02:2025 Security Misconfiguration',
    'headers',
    '/',
    'Server header exposed a product name in the demonstration fixture.',
    'Remove unnecessary version and server headers.',
  ],
] as const
export function mockScans(): Scan[] {
  return [
    'Juice Shop · baseline',
    'DVWA · authentication',
    'Lab · interrupted',
    'Lab · scheduled',
  ].map((name, i) => {
    const id = `demo-${i + 1}`
    const target = i === 1 ? 'http://127.0.0.1:8080' : 'http://127.0.0.1:3000'
    const findings = (i > 1 ? [] : i === 1 ? specs.slice(1, 3) : specs).map(
      (s, j) =>
        findingSchema.parse({
          id: `${id}-f${j}`,
          title: s[0],
          severity: s[1],
          cvss_score: s[2],
          category: s[3],
          plugin: s[4],
          target: `${target}${s[5]}`,
          evidence: s[6],
          recommendation: s[7],
          timestamp: `2026-11-21T14:${String(10 + j * 2).padStart(2, '0')}:00+00:00`,
          epss: j === 0 ? 0.82 : null,
        }),
    )
    return {
      id,
      name,
      target,
      source: 'mock',
      status: (['completed', 'running', 'failed', 'queued'] as const)[i],
      progress: [100, 64, 28, 0][i],
      startedAt: i === 3 ? null : '2026-11-21T14:00:00+00:00',
      finishedAt: i === 0 ? '2026-11-21T14:24:00+00:00' : null,
      error: i === 2 ? 'Demo fixture: target connection timed out.' : undefined,
      report: makeReport(findings, {
        target,
        scan_id: id,
        tool: 'AAST · demonstration fixture',
        generated_at: '2026-11-21T14:24:00+00:00',
      }),
    }
  })
}
