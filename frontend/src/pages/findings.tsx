import { sourceLabels } from '@/lib/provenance'
import { formatDate } from '@/lib/dates'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, FileCode2, ShieldCheck } from 'lucide-react'
import { useScans } from '@/data/store'
import { FindingsTable } from '@/components/findings-table'
import { Empty, SeverityBadge } from '@/components/common'
export default function Findings() {
  const { scans } = useScans()
  return (
    <>
      <div className="page-intro">
        <div>
          <h1>Vulnerability findings</h1>
          <p>Search, filter, and inspect reported evidence.</p>
        </div>
      </div>
      <section className="panel">
        <FindingsTable
          rows={scans.flatMap((s) =>
            s.report.findings.map((finding) => ({
              finding,
              scanId: s.id,
              source: s.source,
            })),
          )}
        />
      </section>
    </>
  )
}
export function FindingDetail() {
  const { scanId, findingId } = useParams()
  const { scans } = useScans()
  const scan = scans.find((s) => s.id === scanId)
  const f = scan?.report.findings.find((f) => f.id === findingId)
  if (!f || !scan)
    return (
      <Empty
        title="Finding not found"
        detail="This finding may belong to an in-memory report that needs to be imported again."
      />
    )
  return (
    <>
      <Link to={`/scans/${encodeURIComponent(scan.id)}`} className="text-link">
        <ArrowLeft size={16} /> Back to scan
      </Link>
      <div className="page-intro">
        <div>
          <p className="eyebrow">{f.category}</p>
          <h1>{f.title}</h1>
          <p className="mono">{f.target || 'Target not provided'}</p>
        </div>
        <SeverityBadge severity={f.severity} />
      </div>
      {scan.source === 'mock' && (
        <div className="notice">
          Demonstration finding · sample evidence for interface testing.
        </div>
      )}
      <div className="detail-grid investigation-grid">
        <section className="panel padded">
          <h2>Finding context</h2>
          <dl>
            <dt>Finding ID</dt>
            <dd className="mono">{f.id}</dd>
            <dt>Data source</dt>
            <dd>
              <span className={`source-label source-${scan.source}`}>
                {sourceLabels[scan.source]}
              </span>
            </dd>
            <dt>Plugin</dt>
            <dd>{f.plugin || 'Not provided'}</dd>
            <dt>Observed</dt>
            <dd>{formatDate(f.timestamp)}</dd>
            <dt>Reported CVSS</dt>
            <dd>{f.cvss_score.toFixed(1)} / 10</dd>
            <dt>EPSS</dt>
            <dd>
              {f.epss === null
                ? 'Not provided'
                : `${(f.epss * 100).toFixed(2)}%`}
            </dd>
            <dt>CVSS vector</dt>
            <dd className="mono">{f.cvss_vector || 'Not provided'}</dd>
          </dl>
          <p className="subtle">
            Scores are displayed as reported. P4's current scoring model is an
            approximation; no scores are recalculated here.
          </p>
        </section>
        <section className="panel padded">
          <h2>
            <ShieldCheck size={18} /> Remediation
          </h2>
          <p className="preserve">
            {f.recommendation || 'No remediation supplied.'}
          </p>
          <div className="notice">
            Review the evidence and validate the fix in the authorized lab.
          </div>
        </section>
      </div>
      <section className="panel padded">
        <h2>
          <FileCode2 size={18} /> Evidence
        </h2>
        <pre>{f.evidence || 'No evidence supplied.'}</pre>
        <div className="evidence-grid">
          <div>
            <h3>Request</h3>
            <pre>{f.request || 'Not provided'}</pre>
          </div>
          <div>
            <h3>Response</h3>
            <pre>{f.response || 'Not provided'}</pre>
          </div>
        </div>
      </section>
    </>
  )
}
