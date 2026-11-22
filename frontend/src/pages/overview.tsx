import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts'
import { useScans } from '@/data/store'
import { severities } from '@/data/schema'
import { matchesSource, sourceLabels } from '@/lib/provenance'
import { FindingsTable } from '@/components/findings-table'
import { Empty, StatusBadge } from '@/components/common'
import { Button } from '@/components/ui/button'

export default function Overview() {
  const { scans: allScans } = useScans()
  const [source, setSource] = useState('all')
  const scans = allScans.filter((scan) => matchesSource(scan.source, source))
  const rows = scans.flatMap((scan) =>
    scan.report.findings.map((finding) => ({
      finding,
      scanId: scan.id,
      source: scan.source,
    })),
  )
  const counts = severities.map((name, i) => ({
    name,
    value: rows.filter((r) => r.finding.severity === name).length,
    color: ['#f28b91', '#e9a665', '#ddc46a', '#79b6d8', '#9ba6b5'][i],
  }))
  const categories = [...new Set(rows.map((r) => r.finding.category))]
    .map((category) => ({
      name: category,
      count: rows.filter((r) => r.finding.category === category).length,
    }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
  const metrics = [
    {
      label: 'Scans / snapshots',
      value: scans.length,
      note: `${scans.filter((s) => s.status === 'snapshot').length} imported`,
    },
    { label: 'Findings', value: rows.length, note: 'Within selected source' },
    {
      label: 'Critical / high',
      value: counts[0].value + counts[1].value,
      note: `${counts[0].value} critical · ${counts[1].value} high`,
      urgent: true,
    },
    {
      label: 'Running scans',
      value: scans.filter((s) => s.status === 'running').length,
      note: scans.some((s) => s.source === 'mock')
        ? 'Includes static demo status'
        : 'Reported scan status',
    },
  ]
  return (
    <>
      <div className="page-intro">
        <h1>Overview</h1>
        <div className="page-actions">
          <label className="sr-only" htmlFor="overview-source">
            Overview data source
          </label>
          <select
            id="overview-source"
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            <option value="all">All data sources</option>
            <option value="mock">Demo only</option>
            <option value="imported">Imported reports only</option>
            <option value="api">API only</option>
          </select>
          <Button size="sm" asChild>
            <Link to="/reports">Import report</Link>
          </Button>
        </div>
      </div>
      <div className="stats-grid" aria-label="Operational metrics">
        {metrics.map((m) => (
          <article
            className={`stat-card${m.urgent ? ' metric-attention' : ''}`}
            key={m.label}
          >
            <span>{m.label}</span>
            <strong>{m.value}</strong>
            <small>{m.note}</small>
          </article>
        ))}
      </div>
      <section className="panel" aria-labelledby="priority-title">
        <div className="panel-heading">
          <div>
            <h2 id="priority-title">
              Priority review{' '}
              <span className="count-label">{rows.length} findings</span>
            </h2>
            <p>
              Highest severity first, then reported CVSS · showing up to 5
              findings
            </p>
          </div>
          <Link to="/findings" className="text-link">
            Investigate all findings →
          </Link>
        </div>
        <FindingsTable rows={rows} compact />
      </section>
      <div className="chart-grid">
        <section className="panel" aria-labelledby="severity-title">
          <div className="panel-heading">
            <h2 id="severity-title">Severity distribution</h2>
            <span className="subtle">{rows.length} findings</span>
          </div>
          {rows.length ? (
            <div className="severity-summary">
              <div
                className="severity-stack"
                role="img"
                aria-label={counts
                  .map((c) => `${c.name}: ${c.value}`)
                  .join(', ')}
              >
                {counts
                  .filter((c) => c.value > 0)
                  .map((c) => (
                    <div
                      key={c.name}
                      style={{ flexGrow: c.value, backgroundColor: c.color }}
                      title={`${c.name}: ${c.value}`}
                    />
                  ))}
              </div>
              <ul className="severity-legend">
                {counts.map((c) => (
                  <li key={c.name}>
                    <span>
                      <i style={{ backgroundColor: c.color }} />
                      {c.name.toLowerCase()}
                    </span>
                    <strong>{c.value}</strong>
                    <small>{((c.value / rows.length) * 100).toFixed(1)}%</small>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <Empty
              title="No findings in this source"
              detail="Choose another source or import a report."
            />
          )}
        </section>
        <section className="panel" aria-labelledby="owasp-title">
          <div className="panel-heading">
            <h2 id="owasp-title">OWASP categories</h2>
            <span className="subtle">As reported</span>
          </div>
          {categories.length ? (
            <div
              className="category-chart"
              role="img"
              aria-label={categories
                .map((c) => `${c.name}: ${c.count}`)
                .join(', ')}
            >
              <ResponsiveContainer
                width="100%"
                height={Math.max(144, categories.length * 32)}
                minWidth={0}
              >
                <BarChart
                  data={categories}
                  layout="vertical"
                  margin={{ top: 0, right: 32, left: 0, bottom: 0 }}
                  barCategoryGap={8}
                >
                  <XAxis
                    type="number"
                    hide
                    domain={[0, 'dataMax']}
                    allowDecimals={false}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={104}
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: '#b1b7c1', fontSize: 11 }}
                    tickFormatter={(value) => String(value).split(' ')[0]}
                  />
                  <Tooltip
                    cursor={{ fill: '#ffffff04' }}
                    contentStyle={{
                      background: '#20242b',
                      border: '1px solid #3a414c',
                      borderRadius: 4,
                      color: '#edf0f4',
                      fontSize: 12,
                    }}
                  />
                  <Bar
                    dataKey="count"
                    name="Findings"
                    fill="#66bfb2"
                    radius={[0, 3, 3, 0]}
                    maxBarSize={14}
                    isAnimationActive={false}
                    label={{ position: 'right', fill: '#c9ced6', fontSize: 11 }}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <Empty
              title="No categories available"
              detail="Categories are taken directly from findings."
            />
          )}
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Recent scans</h2>
          <Link to="/scans" className="text-link">
            Scan history →
          </Link>
        </div>
        {scans.length ? (
          <div className="recent-scans">
            {scans.slice(0, 3).map((s) => (
              <Link key={s.id} to={`/scans/${encodeURIComponent(s.id)}`}>
                <span>
                  <strong>{s.name}</strong>
                  <small className="mono">
                    {s.target || 'Target unavailable'}
                  </small>
                </span>
                <span className={`source-label source-${s.source}`}>
                  {sourceLabels[s.source]}
                </span>
                <StatusBadge status={s.status} />
              </Link>
            ))}
          </div>
        ) : (
          <Empty
            title="No scans in this source"
            detail="Choose another source or import a report."
          />
        )}
      </section>
    </>
  )
}
