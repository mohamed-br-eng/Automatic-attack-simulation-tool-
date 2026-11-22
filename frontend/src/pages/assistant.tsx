import { Button } from '@/components/ui/button'
export default function Assistant() {
  return (
    <>
      <div className="page-intro">
        <div>
          <h1>AI assistant</h1>
          <p>Service status and planned capabilities.</p>
        </div>
        <span className="tag">Unavailable</span>
      </div>
      <section className="panel assistant-panel">
        <div className="panel-heading">
          <h2>Service unavailable</h2>
        </div>
        <div className="padded">
          <p>
            The AI service has not been implemented. No requests are sent, and
            no generated analysis is displayed.
          </p>
          <dl className="capability-list">
            <dt>Assistant messages</dt>
            <dd>Unavailable · awaiting AI service</dd>
            <dt>Remediation retrieval</dt>
            <dd>Planned · OWASP / CWE sources with citations</dd>
            <dt>Risk prioritization</dt>
            <dd>Planned · reviewed recommendations with rationale</dd>
            <dt>Anomaly detection</dt>
            <dd>Planned · model results with confidence and provenance</dd>
          </dl>
          <label className="field-label" htmlFor="assistant-prompt">
            Assistant message (unavailable)
          </label>
          <div className="composer">
            <input
              id="assistant-prompt"
              disabled
              placeholder="AI service required"
            />
            <Button disabled aria-label="Send message (unavailable)">
              Send
            </Button>
          </div>
        </div>
      </section>
    </>
  )
}
