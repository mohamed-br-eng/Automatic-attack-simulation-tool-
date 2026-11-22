import { AlertCircle, Inbox, LoaderCircle } from 'lucide-react'
import { Button } from './ui/button'
import type { Severity } from '@/data/schema'
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge sev-${severity.toLowerCase()}`}>
      <span aria-hidden="true">●</span> {severity.toLowerCase()}
    </span>
  )
}
export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge status-${status}`}>
      <span aria-hidden="true">●</span> {status}
    </span>
  )
}
export function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty">
      <Inbox size={30} />
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  )
}
export function Loading() {
  return (
    <div className="empty" role="status">
      <LoaderCircle className="animate-spin" />
      <p>Loading scan data…</p>
    </div>
  )
}
export function ErrorState({
  error,
  retry,
}: {
  error: Error
  retry?: () => void
}) {
  return (
    <div role="alert" className="error-state">
      <AlertCircle />
      <div>
        <h3>Unable to load data</h3>
        <p>{error.message}</p>
        {retry && (
          <Button variant="outline" onClick={retry}>
            Try again
          </Button>
        )}
      </div>
    </div>
  )
}
