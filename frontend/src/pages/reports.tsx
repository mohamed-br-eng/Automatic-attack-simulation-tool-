import { useState, type ChangeEvent } from 'react'
import { Upload, CheckCircle2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { z } from 'zod'
import { fromP4, fromP3, defaultP3Config, parseP3Config } from '@/data/adapters'
import { useScans } from '@/data/store'
import { Button } from '@/components/ui/button'
export default function Reports() {
  const { addScan, clearImports, scans } = useScans()
  const [mode, setMode] = useState('p4')
  const [config, setConfig] = useState(JSON.stringify(defaultP3Config, null, 2))
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [busy, setBusy] = useState(false)
  async function importFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      if (file.size > 10 * 1024 * 1024)
        throw new Error('Report exceeds the 10 MB import limit.')
      const input: unknown = JSON.parse(
        (await file.text()).replace(/^\uFEFF/, ''),
      )
      const scan =
        mode === 'p4'
          ? fromP4(input)
          : fromP3(input, parseP3Config(config), {
              scan_id: file.name,
              target: '',
              tool: 'P3 configurable import',
              generated_at: new Date().toISOString(),
            })
      addScan(scan)
      setSuccess(
        `Imported ${scan.report.findings.length} findings from ${file.name}.`,
      )
    } catch (cause) {
      setError(
        cause instanceof z.ZodError
          ? cause.issues
              .slice(0, 6)
              .map((i) => `${i.path.join('.') || 'Report'}: ${i.message}`)
              .join('\n')
          : cause instanceof Error
            ? cause.message
            : 'Import failed.',
      )
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <div className="page-intro">
        <div>
          <h1>Report imports</h1>
          <p>Validate and review P4 reports or configure a P3 import.</p>
        </div>
        <span className="tag">Local processing</span>
      </div>
      <div className="detail-grid">
        <section className="panel padded">
          <h2>Import scan results</h2>
          <p className="subtle">
            JSON is validated before it enters the dashboard. Files stay in this
            browser session and are never uploaded.
          </p>
          <label className="field-label" htmlFor="report-format">
            Report format
          </label>
          <select
            id="report-format"
            value={mode}
            onChange={(e) => {
              setMode(e.target.value)
              setError('')
              setSuccess('')
            }}
          >
            <option value="p4">P4 · meta / summary / findings</option>
            <option value="p3">P3 · configurable adapter (provisional)</option>
          </select>
          <label className="upload-zone">
            <Upload size={30} />
            <strong>
              {busy ? 'Validating report…' : 'Choose a JSON report'}
            </strong>
            <span>Maximum 10 MB · 20,000 findings</span>
            <input
              type="file"
              accept=".json,application/json"
              aria-label="Import JSON report"
              disabled={busy}
              onChange={(event) => {
                void importFile(event)
              }}
            />
          </label>
          {error && (
            <pre className="import-error" role="alert">
              {error}
            </pre>
          )}
          {success && (
            <div className="success" role="status">
              <CheckCircle2 size={18} />
              <span>
                {success} <Link to="/scans">View scans →</Link>
              </span>
            </div>
          )}
        </section>
        <section className="panel padded">
          <h2>Contract-aware by design</h2>
          <ul className="notes-list">
            <li>
              P4 findings retain their original IDs, evidence, severity,
              timestamps, and recommendations.
            </li>
            <li>
              Report generation time is distinct from scan start and finish.
              Unavailable fields remain unavailable.
            </li>
            <li>
              Summary counts and posture must agree with the findings. Invalid
              imports leave existing data untouched.
            </li>
            <li>
              Imports are held in memory. Refreshing the page clears them; keep
              the original JSON.
            </li>
          </ul>
          <Button
            variant="outline"
            disabled={
              !scans.some((s) => s.source === 'p3' || s.source === 'p4')
            }
            onClick={() => {
              clearImports()
              setSuccess('Imported reports cleared.')
              setError('')
            }}
          >
            Clear imported reports
          </Button>
        </section>
      </div>
      {mode === 'p3' && (
        <section className="panel padded">
          <h2>P3 field mapping</h2>
          <p className="subtle">
            Provisional configuration, not a claim about P3's final schema. Use
            dot-separated paths; required evidence and timestamps must come from
            the source. The import time is used only for report metadata.
          </p>
          <label htmlFor="p3-config" className="field-label">
            Adapter configuration (JSON)
          </label>
          <textarea
            id="p3-config"
            spellCheck={false}
            value={config}
            onChange={(e) => setConfig(e.target.value)}
            rows={20}
          />
        </section>
      )}
    </>
  )
}
