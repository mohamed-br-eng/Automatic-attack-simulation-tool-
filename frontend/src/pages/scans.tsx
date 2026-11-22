import { sourceLabels } from '@/lib/provenance'
import { formatDate } from '@/lib/dates'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Clock3 } from 'lucide-react'
import { useScans } from '@/data/store'
import { Empty, StatusBadge } from '@/components/common'
import { FindingsTable } from '@/components/findings-table'
export default function Scans() {
  const { scans } = useScans()
  return (
    <>
      <div className="page-intro">
        <div>
          <h1>Scan history</h1>
          <p>Inspect progress, results, and imported report snapshots.</p>
        </div>
        <span className="tag">{scans.length} scans</span>
      </div>
      <section className="panel">
        {scans.length ? (
          <div className="table-scroll">
            <table>
              <caption className="sr-only">Scan history</caption>
              <thead>
                <tr>
                  <th>Scan / target</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Findings</th>
                  <th>Source</th>
                  <th>Started</th>
                  <th>
                    <span className="sr-only">Details</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link
                        className="finding-link"
                        to={`/scans/${encodeURIComponent(s.id)}`}
                      >
                        {s.name}
                      </Link>
                      <small className="mono">
                        {s.target || 'Not provided'}
                      </small>
                    </td>
                    <td>
                      <StatusBadge status={s.status} />
                    </td>
                    <td>
                      {s.progress === null ? (
                        'Not provided'
                      ) : (
                        <div className="progress-cell">
                          <progress
                            aria-label={`${s.name} progress`}
                            value={s.progress}
                            max={100}
                          />
                          <span>{s.progress}%</span>
                        </div>
                      )}
                    </td>
                    <td>{s.report.findings.length}</td>
                    <td>
                      <span className={`source-label source-${s.source}`}>
                        {sourceLabels[s.source]}
                      </span>
                    </td>
                    <td>{formatDate(s.startedAt)}</td>
                    <td>
                      <ArrowRight size={16} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No scans loaded"
            detail="Import a report to begin reviewing results."
          />
        )}
      </section>
    </>
  )
}
export function ScanDetail() {
  const { scanId } = useParams()
  const { scans } = useScans()
  const scan = scans.find((s) => s.id === scanId)
  if (!scan)
    return (
      <Empty
        title="Scan not found"
        detail="Imported reports live in memory. Reimport the report if this page was refreshed."
      />
    )
  const events = [...scan.report.findings].sort(
    (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
  )
  return (
    <>
      <Link className="text-link" to="/scans">
        <ArrowLeft size={16} /> Scan history
      </Link>
      <div className="page-intro">
        <div>
          <p className="eyebrow">SCAN DETAILS · {scan.source.toUpperCase()}</p>
          <h1>{scan.name}</h1>
          <p className="mono">{scan.target || 'Target not provided'}</p>
        </div>
        <StatusBadge status={scan.status} />
      </div>
      {scan.source === 'mock' && (
        <div className="notice">
          Demonstration fixture. Progress and lifecycle events are static sample
          data.
        </div>
      )}
      {scan.error && (
        <div className="error-state" role="alert">
          {scan.error}
        </div>
      )}
      <div className="detail-grid">
        <section className="panel padded">
          <h2>Scan context</h2>
          <dl>
            <dt>Report ID</dt>
            <dd className="mono">
              {scan.report.meta.scan_id || 'Not provided'}
            </dd>
            <dt>Started</dt>
            <dd>{formatDate(scan.startedAt)}</dd>
            <dt>Finished</dt>
            <dd>{formatDate(scan.finishedAt)}</dd>
            <dt>Report generated</dt>
            <dd>{formatDate(scan.report.meta.generated_at)}</dd>
            <dt>Producer</dt>
            <dd>{scan.report.meta.tool}</dd>
            <dt>Progress</dt>
            <dd>
              {scan.progress === null
                ? 'Not provided in report'
                : `${scan.progress}%`}
            </dd>
          </dl>
        </section>
        <section className="panel padded">
          <h2>
            <Clock3 size={18} /> Scan timeline
          </h2>
          <p className="subtle">
            {scan.status === 'snapshot'
              ? 'Finding timestamps and report generation only; scan lifecycle is unavailable.'
              : 'Chronological events from this scan.'}
          </p>
          <ol className="timeline">
            {scan.startedAt && (
              <li>
                <time>{formatDate(scan.startedAt)}</time>
                <strong>Scan started</strong>
              </li>
            )}
            {events.map((f) => (
              <li key={f.id}>
                <time>{formatDate(f.timestamp)}</time>
                <Link
                  to={`/scans/${encodeURIComponent(scan.id)}/findings/${encodeURIComponent(f.id)}`}
                >
                  {f.title}
                </Link>
              </li>
            ))}
            <li>
              <time>{formatDate(scan.report.meta.generated_at)}</time>
              <strong>Report snapshot generated</strong>
            </li>
            {scan.finishedAt && (
              <li>
                <time>{formatDate(scan.finishedAt)}</time>
                <strong>Scan completed</strong>
              </li>
            )}
          </ol>
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>Scan findings</h2>
        </div>
        <FindingsTable
          rows={scan.report.findings.map((finding) => ({
            finding,
            scanId: scan.id,
            source: scan.source,
          }))}
        />
      </section>
    </>
  )
}
