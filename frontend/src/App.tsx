import { FormEvent, useState } from 'react'

import './app.css'

type AuditStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR'

type Finding = {
  control_id: string
  title: string
  status: AuditStatus
  evidence: string[]
  message: string
  risk: string | null
  recommendation: string | null
}

type AuditReport = {
  report_id: string
  expires_at: string
  fortiguard: { status: string; detail: string }
  findings: Finding[]
}

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [report, setReport] = useState<AuditReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const form = new FormData()
      form.append('configuration', file)
      const response = await fetch('/api/audits', { method: 'POST', body: form })
      if (!response.ok) throw new Error(`Audit refusé (HTTP ${response.status})`)
      setReport((await response.json()) as AuditReport)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Audit impossible')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main>
      <header>
        <p className="eyebrow">SNS Security · usage interne</p>
        <h1>Vysion <span>v2</span></h1>
        <p>Socle modulaire d’audit FortiGate</p>
      </header>

      <section className="panel">
        <h2>Nouvel audit</h2>
        <form onSubmit={submit}>
          <label htmlFor="configuration">Configuration FortiGate</label>
          <input
            id="configuration"
            name="configuration"
            type="file"
            accept=".conf,.txt,text/plain"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <button type="submit" disabled={!file || loading}>
            {loading ? 'Audit en cours…' : 'Lancer l’audit'}
          </button>
        </form>
        {error && <p role="alert" className="error">{error}</p>}
      </section>

      {report && (
        <section className="results" aria-live="polite">
          <div className="results-header">
            <div>
              <p className="eyebrow">Rapport {report.report_id.slice(0, 8)}</p>
              <h2>Résultats</h2>
            </div>
            <div className="download-links" aria-label="Téléchargements du rapport">
              <a href={`/api/reports/${report.report_id}.json`}>Télécharger le JSON</a>
              <a href={`/api/reports/${report.report_id}.docx`}>Télécharger le DOCX</a>
              <a href={`/api/reports/${report.report_id}.xlsx`}>Télécharger le XLSX</a>
            </div>
          </div>
          <p>FortiGuard : <strong>{report.fortiguard.status}</strong></p>
          <div className="finding-grid">
            {report.findings.map((finding) => (
              <article key={finding.control_id}>
                <span className={`status status-${finding.status.toLowerCase()}`}>
                  {finding.status}
                </span>
                <p className="control-id">{finding.control_id}</p>
                <h3>{finding.title}</h3>
                <p>{finding.message}</p>
                {finding.recommendation && <p><strong>Action :</strong> {finding.recommendation}</p>}
              </article>
            ))}
          </div>
        </section>
      )}
    </main>
  )
}

export default App
