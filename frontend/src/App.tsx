import { FormEvent, useState } from 'react'

import './app.css'

type AuditStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR'

type RiskAssessment = {
  summary: string
  impact?: string | null
  likelihood?: string | null
  treatment?: string | null
}

type EvidenceItem = {
  section?: string | null
  entry?: string | null
  directive?: string | null
  tokens?: string[]
  line?: number | null
  certainty?: string
}

type AffectedObject = {
  name: string
  object_type?: string
}

type Finding = {
  control_id: string
  title: string
  status: AuditStatus
  category?: string
  priority?: string
  severity?: string
  applicability?: string
  evidence?: string[]
  evidence_items?: EvidenceItem[]
  affected_objects?: AffectedObject[]
  message: string
  risk?: RiskAssessment | string | null
  recommendation?: string | null
  remediation?: string | null
  customer_approval?: boolean | null
}

type AuditContext = {
  selected_wans?: string[] | null
  client?: string | null
  site?: string | null
  ha?: boolean | null
  mpls?: boolean | null
  utm_license?: boolean | null
  operator_provenance?: {
    source: string
    operator?: string | null
    method?: string | null
  } | null
}

type AuditReport = {
  schema_version?: number
  report_id: string
  expires_at: string
  context?: AuditContext
  fortiguard: { status: string; detail: string }
  findings: Finding[]
}

type ApiErrorDetail = {
  detail?: string | Array<{ msg?: string }>
}

function display(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Non renseigné'
  if (typeof value === 'boolean') return value ? 'Oui' : 'Non'
  return String(value)
}

function riskSummary(risk: Finding['risk']): string {
  if (!risk) return 'Non renseigné'
  if (typeof risk === 'string') return risk
  return risk.summary
}

function evidenceSummary(finding: Finding): string {
  if (finding.evidence_items?.length) {
    return finding.evidence_items.map((item) => {
      const location = [item.section, item.entry, item.directive].filter(Boolean).join(' · ')
      const tokens = item.tokens?.join(' ') ?? ''
      const line = item.line ? `ligne ${item.line}` : ''
      return [location, tokens, line, item.certainty].filter(Boolean).join(' · ')
    }).join(' | ')
  }
  return finding.evidence?.join(' | ') || 'Non renseigné'
}

async function auditError(response: Response): Promise<Error> {
  try {
    const payload = (await response.json()) as ApiErrorDetail
    const detail = typeof payload.detail === 'string'
      ? payload.detail
      : payload.detail?.map((item) => item.msg).filter(Boolean).join(' · ')
    if (detail) return new Error(`Audit refusé : ${detail}`)
  } catch {
    // The HTTP status remains available when the response is not valid JSON.
  }
  return new Error(`Audit refusé (HTTP ${response.status})`)
}

function ContextSummary({ context }: { context: AuditContext }) {
  const provenance = context.operator_provenance
  return (
    <div className="context-summary" aria-label="Contexte de l’audit">
      <h3>Contexte opérateur</h3>
      <dl>
        <div><dt>Client</dt><dd>{display(context.client)}</dd></div>
        <div><dt>Site</dt><dd>{display(context.site)}</dd></div>
        <div><dt>WAN sélectionnées</dt><dd>{display(context.selected_wans?.join(', '))}</dd></div>
        <div><dt>HA</dt><dd>{display(context.ha)}</dd></div>
        <div><dt>MPLS</dt><dd>{display(context.mpls)}</dd></div>
        <div><dt>Licence UTM</dt><dd>{display(context.utm_license)}</dd></div>
        <div><dt>Provenance</dt><dd>{display(provenance?.source)}</dd></div>
        <div><dt>Opérateur</dt><dd>{display(provenance?.operator)}</dd></div>
      </dl>
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article>
      <span className={`status status-${finding.status.toLowerCase()}`}>
        {finding.status}
      </span>
      <p className="control-id">{finding.control_id}</p>
      <h3>{finding.title}</h3>
      <div className="finding-metadata">
        <span>Catégorie : <strong>{display(finding.category)}</strong></span>
        <span>Priorité : <strong>{display(finding.priority)}</strong></span>
        <span>Sévérité : <strong>{display(finding.severity)}</strong></span>
        <span>Applicabilité : <strong>{display(finding.applicability)}</strong></span>
      </div>
      <p>{finding.message}</p>
      <p><strong>Preuve :</strong> {evidenceSummary(finding)}</p>
      <p><strong>Objets affectés :</strong> {finding.affected_objects?.map((item) => `${item.object_type ?? 'unknown'} / ${item.name}`).join(', ') || 'Non renseigné'}</p>
      <p><strong>Risque :</strong> {riskSummary(finding.risk)}</p>
      {typeof finding.risk === 'object' && finding.risk && (
        <ul className="risk-details">
          <li>Impact : {display(finding.risk.impact)}</li>
          <li>Probabilité : {display(finding.risk.likelihood)}</li>
          <li>Traitement : {display(finding.risk.treatment)}</li>
        </ul>
      )}
      <p><strong>Recommandation :</strong> {display(finding.recommendation)}</p>
      <p><strong>Remédiation :</strong> {display(finding.remediation)}</p>
      <p><strong>Approbation client :</strong> {display(finding.customer_approval)}</p>
    </article>
  )
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
    setReport(null)
    try {
      const form = new FormData()
      form.append('configuration', file)
      const response = await fetch('/api/audits', { method: 'POST', body: form })
      if (!response.ok) throw await auditError(response)
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
              {report.schema_version && <p>Schéma {report.schema_version}</p>}
            </div>
            <div className="download-links" aria-label="Téléchargements du rapport">
              <a href={`/api/reports/${report.report_id}.json`}>Télécharger le JSON</a>
              <a href={`/api/reports/${report.report_id}.docx`}>Télécharger le DOCX</a>
              <a href={`/api/reports/${report.report_id}.xlsx`}>Télécharger le XLSX</a>
            </div>
          </div>
          {report.context && <ContextSummary context={report.context} />}
          <p>FortiGuard : <strong>{report.fortiguard.status}</strong></p>
          <div className="finding-grid">
            {report.findings.map((finding) => <FindingCard key={finding.control_id} finding={finding} />)}
          </div>
        </section>
      )}
    </main>
  )
}

export default App
