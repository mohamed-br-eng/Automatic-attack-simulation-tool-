import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Search } from 'lucide-react'
import { selectFindings } from '@/data/adapters'
import { severities, type Finding, type Scan } from '@/data/schema'
import { matchesSource, sourceLabels } from '@/lib/provenance'
import { formatDate } from '@/lib/dates'
import { Input } from './ui/input'
import { Button } from './ui/button'
import { SeverityBadge, Empty } from './common'

export interface FindingRow {
  finding: Finding
  scanId: string
  source: Scan['source']
}
export function FindingsTable({
  rows,
  compact = false,
}: {
  rows: FindingRow[]
  compact?: boolean
}) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [category, setCategory] = useState('all')
  const [target, setTarget] = useState('all')
  const [source, setSource] = useState('all')
  const [sort, setSort] = useState('severity')
  const [page, setPage] = useState(0)
  const eligible = rows.filter(
    (row) =>
      matchesSource(row.source, source) &&
      (target === 'all' || row.finding.target === target),
  )
  const findings = eligible.map((row) => row.finding)
  const rowByFinding = new Map(eligible.map((row) => [row.finding, row]))
  const filtered = selectFindings(findings, search, severity, category, sort)
  const pageCount = Math.max(1, Math.ceil(filtered.length / 10))
  const activePage = Math.min(page, pageCount - 1)
  const visible = compact
    ? filtered.slice(0, 5)
    : filtered.slice(activePage * 10, activePage * 10 + 10)
  const hasFilters = Boolean(
    search ||
    severity !== 'all' ||
    category !== 'all' ||
    target !== 'all' ||
    source !== 'all',
  )
  function reset() {
    setSearch('')
    setSeverity('all')
    setCategory('all')
    setTarget('all')
    setSource('all')
    setSort('severity')
    setPage(0)
  }
  return (
    <div>
      {!compact && (
        <>
          <div className="filters">
            <div className="search-field">
              <Search size={16} aria-hidden="true" />
              <Input
                aria-label="Search findings"
                placeholder="Search vulnerability, target, plugin, or ID"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value)
                  setPage(0)
                }}
              />
            </div>
            <label className="filter-control">
              Severity
              <select
                aria-label="Filter severity"
                value={severity}
                onChange={(e) => {
                  setSeverity(e.target.value)
                  setPage(0)
                }}
              >
                <option value="all">All severities</option>
                {severities.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label className="filter-control">
              OWASP category
              <select
                aria-label="Filter category"
                value={category}
                onChange={(e) => {
                  setCategory(e.target.value)
                  setPage(0)
                }}
              >
                <option value="all">All categories</option>
                {[...new Set(rows.map((r) => r.finding.category))]
                  .sort()
                  .map((c) => (
                    <option key={c}>{c}</option>
                  ))}
              </select>
            </label>
            <label className="filter-control">
              Target
              <select
                aria-label="Filter target"
                value={target}
                onChange={(e) => {
                  setTarget(e.target.value)
                  setPage(0)
                }}
              >
                <option value="all">All targets</option>
                {[...new Set(rows.map((r) => r.finding.target))]
                  .sort()
                  .map((t) => (
                    <option key={t} value={t}>
                      {t || 'Unavailable'}
                    </option>
                  ))}
              </select>
            </label>
            <label className="filter-control">
              Data source
              <select
                aria-label="Filter data source"
                value={source}
                onChange={(e) => {
                  setSource(e.target.value)
                  setPage(0)
                }}
              >
                <option value="all">All sources</option>
                <option value="mock">Demo</option>
                <option value="imported">P3 / P4 imports</option>
                <option value="api">API</option>
              </select>
            </label>
          </div>
          <div className="table-toolbar">
            <span role="status">
              {filtered.length} of {rows.length} findings
              {hasFilters ? ' · filtered' : ''}
            </span>
            <div>
              {hasFilters && (
                <Button size="sm" variant="ghost" onClick={reset}>
                  Clear filters
                </Button>
              )}
              <label className="sort-control">
                Sort by
                <select
                  aria-label="Sort findings"
                  value={sort}
                  onChange={(e) => {
                    setSort(e.target.value)
                    setPage(0)
                  }}
                >
                  <option value="severity">Severity ↓</option>
                  <option value="score">CVSS ↓</option>
                  <option value="epss">EPSS ↓</option>
                  <option value="newest">Newest first</option>
                  <option value="title">Vulnerability A–Z</option>
                </select>
              </label>
            </div>
          </div>
        </>
      )}
      {visible.length ? (
        <>
          <p className="table-scroll-hint">
            Scroll horizontally to inspect all columns.
          </p>
          <div
            className="table-scroll"
            role="region"
            aria-label="Findings results"
            tabIndex={0}
          >
            <table className="findings-table">
              <caption className="sr-only">Vulnerability findings</caption>
              <thead>
                <tr>
                  <th scope="col">Severity</th>
                  <th scope="col">Vulnerability</th>
                  <th scope="col">Target</th>
                  <th scope="col" className="numeric">
                    CVSS
                  </th>
                  <th scope="col" className="numeric">
                    EPSS
                  </th>
                  <th scope="col">Detection source</th>
                  <th scope="col">Observed</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((f) => {
                  const row = rowByFinding.get(f)!
                  return (
                    <tr key={`${row.scanId}-${f.id}`}>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="vulnerability-cell">
                        <Link
                          className="finding-link"
                          to={`/scans/${encodeURIComponent(row.scanId)}/findings/${encodeURIComponent(f.id)}`}
                        >
                          {f.title}
                        </Link>
                        <small>{f.category}</small>
                      </td>
                      <td className="mono target-cell">
                        {f.target || (
                          <span className="unavailable">Unavailable</span>
                        )}
                      </td>
                      <td className="mono numeric">
                        {f.cvss_score.toFixed(1)}
                      </td>
                      <td className="mono numeric">
                        {f.epss === null ? (
                          <span className="unavailable">Unavailable</span>
                        ) : (
                          `${(f.epss * 100).toFixed(2)}%`
                        )}
                      </td>
                      <td>
                        <span className="mono detection-plugin">
                          {f.plugin || (
                            <span className="unavailable">Unavailable</span>
                          )}
                        </span>
                        <small className={`source-label source-${row.source}`}>
                          {sourceLabels[row.source]}
                        </small>
                      </td>
                      <td className="timestamp-cell">
                        <time dateTime={f.timestamp}>
                          {formatDate(f.timestamp)}
                        </time>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {!compact && (
            <div className="pagination">
              <span>
                {filtered.length ? activePage * 10 + 1 : 0}–
                {Math.min((activePage + 1) * 10, filtered.length)} of{' '}
                {filtered.length} · page {activePage + 1} of {pageCount}
              </span>
              <div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={activePage === 0}
                  onClick={() => setPage(activePage - 1)}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={activePage + 1 >= pageCount}
                  onClick={() => setPage(activePage + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      ) : (
        <Empty
          title="No findings match"
          detail="Try a different search, adjust the filters, or import a report."
        />
      )}
    </div>
  )
}
