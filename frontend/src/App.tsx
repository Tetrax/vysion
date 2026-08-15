import { FormEvent, useMemo, useRef, useState } from 'react'
import pantherImage from './assets/panther.jpg'
import './app.css'

type AuditStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR' | 'NOT_APPLICABLE'
type TriState = '' | 'true' | 'false'
type Step = 'upload' | 'context' | 'wan' | 'options' | 'audit' | 'results'
type EvidenceItem = { section?: string | null; entry?: string | null; directive?: string | null; tokens?: string[]; line?: number | null; certainty?: string; defaulted?: boolean }
type AffectedObject = { name: string; object_type?: string }
type RiskAssessment = { summary: string; impact?: string | null; likelihood?: string | null; treatment?: string | null }
type Finding = {
  control_id: string; title: string; status: AuditStatus; category?: string; priority?: string; severity?: string; applicability?: string
  evidence?: string[]; evidence_items?: EvidenceItem[]; affected_objects?: AffectedObject[]; message: string
  risk?: RiskAssessment | string | null; recommendation?: string | null; remediation?: string | null; customer_approval?: boolean | null
}
type AuditContext = {
  selected_wans?: string[] | null; client?: string | null; site?: string | null; ha?: boolean | null; mpls?: boolean | null; utm_license?: boolean | null
  operator_provenance?: { source: string; operator?: string | null; method?: string | null } | null
}
type AuditReport = { schema_version?: number; report_id: string; expires_at: string; context?: AuditContext; fortiguard: { status: string; detail: string }; findings: Finding[] }
type PreviewInterface = { name: string; role?: string | null }
type PreviewZone = { name: string; interfaces: string[] }
type Preview = { hostname?: string | null; model?: string | null; firmware_version?: string | null; serial_number?: string | null; interfaces: PreviewInterface[]; zones: PreviewZone[]; sdwan_zones: PreviewZone[] }
type ApiErrorDetail = { detail?: string | Array<{ msg?: string }> }
type Filter = 'ALL' | AuditStatus

type WanOption = { name: string; kinds: string[]; interfaces: string[] }

type StepDefinition = { id: Step; label: string }
const STEPS: StepDefinition[] = [
  { id: 'upload', label: 'Upload / inspection' },
  { id: 'context', label: 'Équipement et contexte' },
  { id: 'wan', label: 'Sélection WAN' },
  { id: 'options', label: 'Options d’audit' },
  { id: 'audit', label: 'Audit / progression' },
  { id: 'results', label: 'Résultats' },
]
const STATUS_ORDER: Record<AuditStatus, number> = { FAIL: 0, ERROR: 0, UNKNOWN: 1, PASS: 2, NOT_APPLICABLE: 3 }
const DOMAIN_LABELS: Record<string, string> = { system: 'Système', administration: 'Administration / Identity', identity: 'Administration / Identity', iam: 'Administration / Identity', network: 'Réseau', firewall: 'Firewall', vpn: 'VPN', utm: 'UTM' }
const DOMAIN_ORDER = ['Système', 'Administration / Identity', 'Réseau', 'Firewall', 'VPN', 'UTM', 'Autre']

function buildWanOptions(preview: Preview): WanOption[] {
  const byName = new Map<string, WanOption>()
  function add(name: string, kind: string, interfaces: string[]) {
    const normalized = name.trim()
    if (!normalized) return
    const key = normalized.toLocaleLowerCase()
    const existing = byName.get(key)
    if (existing) {
      if (!existing.kinds.includes(kind)) existing.kinds.push(kind)
      existing.interfaces = [...new Set([...existing.interfaces, ...interfaces.filter(Boolean)])]
      return
    }
    byName.set(key, { name: normalized, kinds: [kind], interfaces: [...new Set(interfaces.filter(Boolean))] })
  }
  preview.interfaces.forEach((item) => add(item.name, item.role === 'wan' ? 'Interface WAN' : 'Interface', []))
  preview.zones.forEach((zone) => add(zone.name, 'Zone', zone.interfaces))
  preview.sdwan_zones.forEach((zone) => add(zone.name, 'SD-WAN', zone.interfaces))
  return [...byName.values()]
}

function display(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Non renseigné'
  if (typeof value === 'boolean') return value ? 'Oui' : 'Non'
  return String(value)
}
function riskSummary(risk: Finding['risk']): string { return !risk ? 'Non renseigné' : typeof risk === 'string' ? risk : risk.summary }
function domainOf(finding: Finding): string {
  const prefix = finding.control_id.split('-')[0].toLowerCase()
  return DOMAIN_LABELS[(finding.category ?? '').toLowerCase()] ?? DOMAIN_LABELS[prefix] ?? 'Autre'
}
async function responseError(response: Response, action: string): Promise<Error> {
  try {
    const payload = (await response.json()) as ApiErrorDetail
    const detail = typeof payload.detail === 'string' ? payload.detail : payload.detail?.map((item) => item.msg).filter(Boolean).join(' · ')
    if (detail) return new Error(`${action} refusé : ${detail}`)
  } catch { /* status fallback */ }
  return new Error(`${action} refusé (HTTP ${response.status})`)
}
function TriStateField({ label, value, onChange }: { label: string; value: TriState; onChange: (value: TriState) => void }) {
  return <label>{label}<select value={value} onChange={(event) => onChange(event.target.value as TriState)}><option value="">Non renseigné</option><option value="true">Oui</option><option value="false">Non</option></select></label>
}
function ContextSummary({ context }: { context: AuditContext }) {
  return <section className="context-summary" aria-label="Contexte de l’audit"><h3>Contexte opérateur</h3><dl>
    <div><dt>Client</dt><dd>{display(context.client)}</dd></div><div><dt>Site</dt><dd>{display(context.site)}</dd></div>
    <div><dt>WAN sélectionnées</dt><dd>{display(context.selected_wans?.join(', '))}</dd></div><div><dt>HA</dt><dd>{display(context.ha)}</dd></div>
    <div><dt>MPLS</dt><dd>{display(context.mpls)}</dd></div><div><dt>Licence UTM</dt><dd>{display(context.utm_license)}</dd></div>
    <div><dt>Provenance</dt><dd>{display(context.operator_provenance?.source)}</dd></div><div><dt>Opérateur</dt><dd>{display(context.operator_provenance?.operator)}</dd></div><div><dt>Méthode</dt><dd>{display(context.operator_provenance?.method)}</dd></div>
  </dl></section>
}
function Evidence({ finding }: { finding: Finding }) {
  const [allEvidence, setAllEvidence] = useState(false)
  const values = finding.evidence_items?.length
    ? finding.evidence_items.map((item) => [item.section, item.entry, item.directive, item.tokens?.join(' '), item.line ? `ligne ${item.line}` : null, item.certainty, item.defaulted ? 'valeur par défaut' : null].filter(Boolean).join(' · '))
    : finding.evidence ?? []
  const shown = allEvidence ? values : values.slice(0, 3)
  if (values.length) return <><ul className="detail-list">{shown.map((item, index) => <li key={index}>{item}</li>)}</ul>{values.length > 3 && <button type="button" className="text-button" aria-expanded={allEvidence} onClick={() => setAllEvidence(!allEvidence)}>{allEvidence ? 'Réduire les preuves' : `Afficher les ${values.length} preuves`}</button>}</>
  return <span>Non renseigné</span>
}
function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const [allObjects, setAllObjects] = useState(false)
  const objects = finding.affected_objects ?? []
  const shown = allObjects ? objects : objects.slice(0, 3)
  return <article className="finding-card" data-testid="finding-card">
    <div className="finding-top"><span className={`status status-${finding.status.toLowerCase()}`}>{finding.status}</span><span className="severity">{display(finding.severity)}</span></div>
    <p className="control-id">{finding.control_id}</p><h3>{finding.title}</h3>
    <div className="compact-meta"><span>{objects.length} objet{objects.length > 1 ? 's' : ''} affecté{objects.length > 1 ? 's' : ''}</span><span>{objects[0]?.object_type ?? 'aucun type'}</span><span>{domainOf(finding)}</span></div>
    <p className="message">{finding.message}</p><p className="risk-line"><strong>Risque :</strong> {riskSummary(finding.risk)}</p>
    <button className="details-button" type="button" aria-expanded={open} aria-controls={`details-${finding.control_id}`} onClick={() => setOpen(!open)}>{open ? 'Masquer les détails' : 'Voir les détails'}</button>
    {open && <div id={`details-${finding.control_id}`} className="finding-details">
      <dl><div><dt>Catégorie</dt><dd>{display(finding.category)}</dd></div><div><dt>Priorité</dt><dd>{display(finding.priority)}</dd></div><div><dt>Applicabilité</dt><dd>{display(finding.applicability)}</dd></div><div><dt>Approbation client</dt><dd>{display(finding.customer_approval)}</dd></div></dl>
      <h4>Preuves</h4><Evidence finding={finding} />
      <h4>Objets affectés</h4>{shown.length ? <ul className="detail-list">{shown.map((item, index) => <li key={`${item.object_type}-${item.name}-${index}`}>{item.object_type ?? 'unknown'} · {item.name}</li>)}</ul> : <p>Non renseigné</p>}
      {objects.length > 3 && <button type="button" className="text-button" aria-expanded={allObjects} onClick={() => setAllObjects(!allObjects)}>{allObjects ? 'Réduire la liste' : `Afficher les ${objects.length} éléments`}</button>}
      {typeof finding.risk === 'object' && finding.risk && <><h4>Analyse du risque</h4><dl><div><dt>Impact</dt><dd>{display(finding.risk.impact)}</dd></div><div><dt>Probabilité</dt><dd>{display(finding.risk.likelihood)}</dd></div><div><dt>Traitement</dt><dd>{display(finding.risk.treatment)}</dd></div></dl></>}
      <h4>Recommandation</h4><p>{display(finding.recommendation)}</p><h4>Remédiation</h4><p>{display(finding.remediation)}</p>
    </div>}
  </article>
}
function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) { return <div className={`stat ${tone ?? ''}`}><span>{label}</span><strong>{value}</strong></div> }
function StepNavigation({ currentStep }: { currentStep: Step }) {
  const currentIndex = STEPS.findIndex((step) => step.id === currentStep)
  return <nav className="steps" aria-label="Parcours d’audit"><ol>
    {STEPS.map((step, index) => <li key={step.id} className={index === currentIndex ? 'current' : index < currentIndex ? 'complete' : ''} aria-current={index === currentIndex ? 'step' : undefined}>
      <span className="step-number" aria-hidden="true">{index + 1}</span><span>{step.label}</span>
    </li>)}
  </ol></nav>
}

function App() {
  const [step, setStep] = useState<Step>('upload')
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<Preview | null>(null)
  const [report, setReport] = useState<AuditReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [client, setClient] = useState('')
  const [site, setSite] = useState('')
  const [ha, setHa] = useState<TriState>('')
  const [mpls, setMpls] = useState<TriState>('')
  const [utmLicense, setUtmLicense] = useState<TriState>('')
  const [selectedWans, setSelectedWans] = useState<string[]>([])
  const [filter, setFilter] = useState<Filter>('ALL')
  const requestGeneration = useRef(0)
  const progressTimer = useRef<number | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  function stopProgress() {
    if (progressTimer.current !== null) {
      window.clearInterval(progressTimer.current)
      progressTimer.current = null
    }
  }
  function startProgress() {
    stopProgress()
    setProgress(10)
    progressTimer.current = window.setInterval(() => setProgress((current) => Math.min(current + 5, 92)), 180)
  }

  async function selectFile(selected: File | null) {
    const generation = ++requestGeneration.current
    stopProgress()
    setProgress(0)
    setFile(selected); setPreview(null); setReport(null); setError(null); setSelectedWans([]); setLoading(false); setStep('upload')
    setClient(''); setSite(''); setHa(''); setMpls(''); setUtmLicense('')
    if (!selected) return
    setPreviewing(true)
    const form = new FormData(); form.append('configuration', selected)
    try {
      const response = await fetch('/api/audits/preview', { method: 'POST', body: form })
      if (!response.ok) throw await responseError(response, 'Inspection')
      const inspected = (await response.json()) as Preview
      if (generation !== requestGeneration.current) return
      setPreview(inspected)
      setSelectedWans(buildWanOptions(inspected).filter((option) => option.kinds.includes('Interface WAN')).map((option) => option.name))
      setStep('context')
    } catch (reason) { if (generation === requestGeneration.current) setError(reason instanceof Error ? reason.message : 'Inspection impossible') }
    finally { if (generation === requestGeneration.current) setPreviewing(false) }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!file || !preview) return
    const generation = requestGeneration.current
    setLoading(true); setError(null); setReport(null); setStep('audit'); startProgress()
    const form = new FormData(); form.append('configuration', file)
    selectedWans.forEach((wan) => form.append('selected_wans', wan))
    if (client) form.append('client', client); if (site) form.append('site', site)
    if (ha) form.append('ha_context', ha); if (mpls) form.append('mpls_context', mpls); if (utmLicense) form.append('utm_license', utmLicense)
    form.append('context_source', 'operator-form'); form.append('context_method', 'manual-selection')
    try {
      const response = await fetch('/api/audits', { method: 'POST', body: form })
      if (!response.ok) throw await responseError(response, 'Audit')
      const audited = (await response.json()) as AuditReport
      if (generation === requestGeneration.current) { stopProgress(); setProgress(100); setReport(audited); setStep('results') }
    } catch (reason) { if (generation === requestGeneration.current) { stopProgress(); setProgress(0); setError(reason instanceof Error ? reason.message : 'Audit impossible'); setStep('options') } }
    finally { if (generation === requestGeneration.current) setLoading(false) }
  }
  function resetAudit() {
    requestGeneration.current += 1
    stopProgress(); setProgress(0)
    setStep('upload'); setFile(null); setPreview(null); setReport(null); setSelectedWans([]); setError(null); setLoading(false); setPreviewing(false)
    setClient(''); setSite(''); setHa(''); setMpls(''); setUtmLicense(''); setFilter('ALL')
    if (fileInput.current) fileInput.current.value = ''
  }
  const ordered = useMemo(() => [...(report?.findings ?? [])].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]), [report])
  const visible = filter === 'ALL' ? ordered : ordered.filter((finding) => finding.status === filter)
  const count = (status: AuditStatus) => ordered.filter((finding) => finding.status === status).length
  const severityCount = (severity: string) => ordered.filter((finding) => finding.severity?.toLowerCase() === severity).length
  const wanOptions = useMemo(() => preview ? buildWanOptions(preview) : [], [preview])

  return <div className="app-shell">
    <header className="hero"><img className="hero-image" src={pantherImage} alt="Panthère Vysion" /><div className="hero-content"><p className="eyebrow">SNS Security · usage interne</p><h1>Vysion <span>v2.1.2</span></h1><p>Audit de configuration FortiGate</p></div></header>
    <main>
      <StepNavigation currentStep={step} />
      <input ref={fileInput} className="visually-hidden" aria-label="Configuration FortiGate" id="configuration" name="configuration" type="file" accept=".conf,.txt,text/plain" onChange={(event) => void selectFile(event.target.files?.[0] ?? null)} />
      {step === 'upload' && <section className="panel upload-panel"><div><p className="section-kicker">Étape 1</p><h2>Inspecter une configuration</h2><p>Le fichier est analysé en mémoire, sans persistance lors de la prévisualisation.</p></div><div className="upload-stack"><label className="upload-control" htmlFor="configuration"><strong>{previewing ? 'Inspection en cours…' : 'Sélectionner un fichier .conf'}</strong><span>{file?.name ?? 'Aucun fichier sélectionné'}</span></label>{file && preview && <button className="primary resume-button" type="button" onClick={() => setStep('context')}>Continuer vers le contexte</button>}</div></section>}
      {error && <p role="alert" className="error">{error}</p>}
      {preview && step === 'context' && <form onSubmit={submit} className="workflow">
        <section className="panel equipment" aria-label="Informations équipement"><div className="section-heading"><div><p className="section-kicker">Étape 2</p><h2>Équipement et contexte</h2></div><span className="safe-badge">Preview sûre</span></div>
          <dl className="device-grid"><div><dt>Hostname</dt><dd>{display(preview.hostname)}</dd></div><div><dt>Modèle</dt><dd>{display(preview.model)}</dd></div><div><dt>Version</dt><dd>FortiOS {display(preview.firmware_version)}</dd></div><div><dt>N° de série</dt><dd>{display(preview.serial_number)}</dd></div><div><dt>Interfaces</dt><dd>{preview.interfaces.length}</dd></div><div><dt>Zones</dt><dd>{preview.zones.map((zone) => zone.name).join(', ') || 'Aucune'}</dd></div><div><dt>SD-WAN</dt><dd>{preview.sdwan_zones.map((zone) => zone.name).join(', ') || 'Non détecté'}</dd></div></dl>
          <div className="context-form"><label>Client<input value={client} onChange={(event) => setClient(event.target.value)} placeholder="Non renseigné" /></label><label>Site<input value={site} onChange={(event) => setSite(event.target.value)} placeholder="Non renseigné" /></label><TriStateField label="HA" value={ha} onChange={setHa} /><TriStateField label="MPLS" value={mpls} onChange={setMpls} /><TriStateField label="Licence UTM" value={utmLicense} onChange={setUtmLicense} /></div>
          <div className="actions guided-actions"><button className="secondary" type="button" onClick={() => setStep('upload')}>Retour à l’upload</button><button className="primary" type="button" onClick={() => setStep('wan')}>Continuer vers la sélection WAN</button></div>
        </section>
      </form>}
      {preview && step === 'wan' && <section className="panel workflow" aria-label="Sélection WAN"><div className="section-heading"><div><p className="section-kicker">Étape 3</p><h2>Sélection WAN</h2></div><span className="safe-badge">Options envoyables</span></div><p className="intro">Sélectionnez les interfaces WAN réellement auditées. Les choix restent conservés lorsque vous revenez au contexte.</p>
        <fieldset className="wan-selection"><legend>Options WAN envoyables</legend><div className="wan-grid">{wanOptions.map((option) => <label key={option.name.toLocaleLowerCase()}><input aria-label={`WAN ${option.name}`} type="checkbox" checked={selectedWans.includes(option.name)} onChange={() => setSelectedWans((current) => current.includes(option.name) ? current.filter((name) => name !== option.name) : [...current, option.name])} /><span><strong>{option.name}</strong><small>{option.kinds.join(' · ')}{option.interfaces.length ? ` · ${option.interfaces.join(', ')}` : ''}</small></span></label>)}</div>{wanOptions.length === 0 && <p className="empty-state">Aucune option nommée et envoyable n’a été fournie par l’inspection.</p>}</fieldset>
        <div className="actions"><button className="secondary" type="button" onClick={() => setStep('context')}>Retour au contexte</button><button className="primary" type="button" onClick={() => setStep('options')}>Continuer vers les options d’audit</button></div>
      </section>}
      {preview && step === 'options' && <form onSubmit={submit} className="workflow"><section className="panel" aria-label="Options d’audit"><div className="section-heading"><div><p className="section-kicker">Étape 4</p><h2>Options d’audit</h2></div><span className="safe-badge">Contexte prêt</span></div><p className="intro">Relisez les informations opérateur avant de lancer l’audit. Les valeurs « Non renseigné » restent inconnues et ne sont pas envoyées.</p><dl className="option-review"><div><dt>WAN sélectionnées</dt><dd>{display(selectedWans.join(', '))}</dd></div><div><dt>HA</dt><dd>{display(ha === '' ? null : ha === 'true')}</dd></div><div><dt>MPLS</dt><dd>{display(mpls === '' ? null : mpls === 'true')}</dd></div><div><dt>Licence UTM</dt><dd>{display(utmLicense === '' ? null : utmLicense === 'true')}</dd></div><div><dt>Provenance</dt><dd>operator-form · manual-selection</dd></div></dl><div className="actions"><button className="secondary" type="button" onClick={() => setStep('wan')}>Retour à la sélection WAN</button><button className="primary" type="submit" disabled={loading}>Lancer l’audit</button></div></section></form>}
      {preview && step === 'audit' && <section className="panel audit-panel" aria-live="polite"><p className="section-kicker">Étape 5</p><h2>Audit en cours</h2><p role="status">Audit en cours : analyse de la configuration et génération du rapport…</p><div className="progress-container"><div className="progress-track" role="progressbar" aria-label="Progression de l’audit" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress} aria-valuetext={`${progress}%`}><span className="progress-fill" style={{ width: `${progress}%` }} /></div><p className="progress-text" aria-live="polite">{progress}%</p></div></section>}
      {report && step === 'results' && <section className="results" aria-live="polite"><div className="results-header"><div><p className="section-kicker">Étape 6 · Rapport {report.report_id.slice(0, 8)}</p><h2>Synthèse et résultats</h2><p>FortiGuard : <strong>{report.fortiguard.status}</strong>{report.schema_version ? ` · Schéma ${report.schema_version}` : ''}</p></div><div className="download-links" aria-label="Téléchargements du rapport"><a href={`/api/reports/${report.report_id}.json`}>JSON</a><a href={`/api/reports/${report.report_id}.docx`}>DOCX</a><a href={`/api/reports/${report.report_id}.xlsx`}>XLSX</a></div></div>
        {report.context && <ContextSummary context={report.context} />}
        <div className="summary-layout"><div className="stats" aria-label="Synthèse des statuts"><Stat label="TOTAL" value={ordered.length} /><Stat label="FAIL" value={count('FAIL')} tone="fail" /><Stat label="ERROR" value={count('ERROR')} tone="fail" /><Stat label="UNKNOWN" value={count('UNKNOWN')} tone="unknown" /><Stat label="PASS" value={count('PASS')} tone="pass" /><Stat label="NOT_APPLICABLE" value={count('NOT_APPLICABLE')} tone="na" /></div><div className="stats severity-stats" aria-label="Synthèse des sévérités"><Stat label="Critical" value={severityCount('critical')} /><Stat label="High" value={severityCount('high')} /><Stat label="Medium" value={severityCount('medium')} /><Stat label="Low" value={severityCount('low')} /><Stat label="Info" value={severityCount('info')} /></div></div>
        <div className="domain-summary" aria-label="Synthèse par domaine">{DOMAIN_ORDER.map((domain) => { const items = ordered.filter((finding) => domainOf(finding) === domain); return <div key={domain}><strong>{domain}</strong><span>{items.length} contrôle{items.length > 1 ? 's' : ''}</span><small>{items.length ? items.sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status])[0].status : '—'}</small></div> })}</div>
        <div className="filters" aria-label="Filtres des résultats">{(['ALL', 'FAIL', 'ERROR', 'UNKNOWN', 'PASS', 'NOT_APPLICABLE'] as Filter[]).map((item) => <button type="button" key={item} className={filter === item ? 'active' : ''} aria-pressed={filter === item} onClick={() => setFilter(item)}>{item === 'ALL' ? 'Tous' : item}</button>)}</div>
        <div className="finding-grid">{visible.map((finding) => <FindingCard key={finding.control_id} finding={finding} />)}</div>
        <div className="results-actions"><button className="secondary" type="button" onClick={resetAudit}>Nouvel audit</button></div>
      </section>}
    </main><footer>Vysion · Audit interne FortiGate</footer>
  </div>
}
export default App
