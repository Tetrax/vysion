import { FormEvent, useMemo, useRef, useState } from 'react'
import pantherImage from './assets/panther.jpg'
import './app.css'

type AuditStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR' | 'NOT_APPLICABLE'
type TriState = '' | 'true' | 'false'
type Step = 'upload' | 'context' | 'wan' | 'options' | 'audit' | 'results'
type EvidenceItem = { section?: string | null; entry?: string | null; directive?: string | null; tokens?: string[]; line?: number | null; certainty?: string; defaulted?: boolean }
type EvidenceValue = string | EvidenceItem
type AffectedObject = { name: string; object_type?: string }
type RiskAssessment = { summary: string; impact?: string | null; likelihood?: string | null; treatment?: string | null }
type Finding = {
  control_id: string; title: string; status: AuditStatus; category?: string; priority?: string; severity?: string; applicability?: string
  evidence?: EvidenceValue[]; evidence_items?: EvidenceItem[]; affected_objects?: AffectedObject[]; message: string
  risk?: RiskAssessment | string | null; recommendation?: string | null; remediation?: string | null; customer_approval?: boolean | null
}
type UtmLicenseDetails = { status?: 'active' | 'inactive' | null; expiration_date?: string | null; provenance?: string | null; manual?: boolean }
type AuditContext = {
  selected_wans?: string[] | null; wan_selections?: { name: string; kind: string; interfaces?: string[]; automatic?: boolean }[] | null
  client?: string | null; site?: string | null; serial_number?: string | null; uptime?: string | null; operator_comment?: string | null; operator?: string | null
  rule_match_statistics?: { unmatched_rules: number; total_rules?: number | null; source: string; method: string } | null
  ha?: boolean | null; mpls?: boolean | null; utm_license?: boolean | null; utm_license_details?: UtmLicenseDetails | null
  operator_provenance?: { source: string; operator?: string | null; method?: string | null } | null
}
type AuditReport = { schema_version?: number; report_id: string; expires_at: string; context?: AuditContext; fortiguard: { status: string; detail: string }; findings: Finding[] }
type PreviewInterface = { name: string; role?: string | null; zone?: string | null }
type PreviewZone = { name: string; interfaces: string[] }
type Preview = { hostname?: string | null; model?: string | null; firmware_version?: string | null; serial_number?: string | null; interfaces: PreviewInterface[]; zones: PreviewZone[]; wan_relations?: { interface: string; zone: string }[]; sdwan_zones: PreviewZone[] }
type ApiErrorDetail = { detail?: string | Array<{ msg?: string }> }
type Filter = 'ALL' | AuditStatus

type WanSelectionKind = 'interface' | 'zone' | 'sdwan' | 'automatic'
type WanOption = { name: string; kinds: string[]; scopes: WanSelectionKind[]; interfaces: string[]; defaultKind: WanSelectionKind }

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
  function add(name: string, kind: WanSelectionKind, label: string, interfaces: string[], preferred = false) {
    const normalized = name.trim()
    if (!normalized) return
    const key = normalized.toLocaleLowerCase()
    const existing = byName.get(key)
    if (existing) {
      if (!existing.scopes.includes(kind)) { existing.scopes.push(kind); existing.kinds.push(label) }
      existing.interfaces = [...new Set([...existing.interfaces, ...interfaces.filter(Boolean)])]
      if (preferred) existing.defaultKind = kind
      return
    }
    byName.set(key, { name: normalized, kinds: [label], scopes: [kind], interfaces: [...new Set(interfaces.filter(Boolean))], defaultKind: kind })
  }
  preview.interfaces.forEach((item) => add(item.name, 'interface', item.role === 'wan' ? 'Interface WAN' : 'Interface', [], item.role === 'wan'))
  preview.zones.forEach((zone) => add(zone.name, 'zone', 'Zone', zone.interfaces))
  preview.sdwan_zones.forEach((zone) => add(zone.name, 'sdwan', 'SD-WAN', zone.interfaces))
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
  const license = context.utm_license_details
  const licenseStatus = license?.status ?? (context.utm_license === true ? 'active' : context.utm_license === false ? 'inactive' : null)
  const wanSummary = context.wan_selections?.map((selection) => `${selection.name} (${selection.kind})`).join(', ') ?? context.selected_wans?.join(', ')
  return <section className="context-summary" aria-label="Contexte de l’audit"><h3>Fiche équipement et contexte opérateur</h3><dl>
    <div><dt>Client</dt><dd>{display(context.client)}</dd></div><div><dt>Site</dt><dd>{display(context.site)}</dd></div>
    <div><dt>Numéro de série</dt><dd>{display(context.serial_number)}</dd></div><div><dt>Uptime</dt><dd>{display(context.uptime)}</dd></div>
    <div><dt>Règles sans match</dt><dd>{display(context.rule_match_statistics?.unmatched_rules)}</dd></div>
    <div><dt>Commentaire contexte</dt><dd>{display(context.operator_comment)}</dd></div>
    <div><dt>Opérateur</dt><dd>{display(context.operator)}</dd></div><div><dt>WAN sélectionnées</dt><dd>{display(wanSummary)}</dd></div>
    <div><dt>HA</dt><dd>{display(context.ha)}</dd></div><div><dt>MPLS / L2L</dt><dd>{display(context.mpls)}</dd></div>
    <div><dt>Licence UTM</dt><dd>{display(licenseStatus)}</dd></div><div><dt>Fin de licence</dt><dd>{display(license?.expiration_date)}</dd></div>
    <div><dt>Provenance licence</dt><dd>{display(license?.provenance)}</dd></div><div><dt>Saisie manuelle</dt><dd>{display(license?.manual)}</dd></div>
    <div><dt>Provenance audit</dt><dd>{display(context.operator_provenance?.source)}</dd></div><div><dt>Analyste</dt><dd>{display(context.operator_provenance?.operator)}</dd></div><div><dt>Méthode</dt><dd>{display(context.operator_provenance?.method)}</dd></div>
  </dl></section>
}
function formatEvidence(item: EvidenceValue): string {
  if (typeof item === 'string') return item
  const details = [
    item.section,
    item.entry,
    item.directive,
    item.tokens?.join(' '),
    item.line !== null && item.line !== undefined ? `ligne ${item.line}` : null,
    item.certainty,
    item.defaulted ? 'valeur par défaut' : null,
  ].filter(Boolean)
  return details.join(' · ') || 'Preuve structurée'
}
function evidenceKey(item: EvidenceItem): string {
  return JSON.stringify([
    item.section,
    item.entry,
    item.directive,
    item.tokens,
    item.line,
    item.certainty,
    item.defaulted,
  ])
}
function Evidence({ finding }: { finding: Finding }) {
  const [allEvidence, setAllEvidence] = useState(false)
  const structuredItems = finding.evidence_items ?? []
  const structuredKeys = new Set(structuredItems.map(evidenceKey))
  const legacyValues = (finding.evidence ?? [])
    .filter((item) => typeof item === 'string' || !structuredKeys.has(evidenceKey(item)))
    .map(formatEvidence)
  const values = [...structuredItems.map(formatEvidence), ...legacyValues]
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
  const [serialNumber, setSerialNumber] = useState('')
  const [uptime, setUptime] = useState('')
  const [unmatchedRules, setUnmatchedRules] = useState('')
  const [operatorComment, setOperatorComment] = useState('')
  const [operator, setOperator] = useState('')
  const [ha, setHa] = useState<TriState>('')
  const [mpls, setMpls] = useState<TriState>('')
  const [utmLicense, setUtmLicense] = useState<TriState>('')
  const [utmLicenseExpiration, setUtmLicenseExpiration] = useState('')
  const [utmLicenseProvenance, setUtmLicenseProvenance] = useState('')
  const [utmLicenseManual, setUtmLicenseManual] = useState(true)
  const [selectedWans, setSelectedWans] = useState<string[]>([])
  const [selectedWanKinds, setSelectedWanKinds] = useState<Record<string, WanSelectionKind>>({})
  const [automaticWan, setAutomaticWan] = useState(false)
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
    setFile(selected); setPreview(null); setReport(null); setError(null); setSelectedWans([]); setSelectedWanKinds({}); setAutomaticWan(false); setLoading(false); setStep('upload')
    setClient(''); setSite(''); setSerialNumber(''); setUptime(''); setUnmatchedRules(''); setOperatorComment(''); setOperator(''); setHa(''); setMpls(''); setUtmLicense(''); setUtmLicenseExpiration(''); setUtmLicenseProvenance(''); setUtmLicenseManual(true)
    if (!selected) return
    setPreviewing(true)
    const form = new FormData(); form.append('configuration', selected)
    try {
      const response = await fetch('/api/audits/preview', { method: 'POST', body: form })
      if (!response.ok) throw await responseError(response, 'Inspection')
      const inspected = (await response.json()) as Preview
      if (generation !== requestGeneration.current) return
      setPreview(inspected)
      setSerialNumber(inspected.serial_number ?? '')
      const defaults = buildWanOptions(inspected).filter((option) => option.kinds.includes('Interface WAN'))
      setSelectedWans(defaults.map((option) => option.name))
      setSelectedWanKinds(Object.fromEntries(defaults.map((option) => [option.name, option.defaultKind])))
      setAutomaticWan(false)
      setStep('context')
    } catch (reason) { if (generation === requestGeneration.current) setError(reason instanceof Error ? reason.message : 'Inspection impossible') }
    finally { if (generation === requestGeneration.current) setPreviewing(false) }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!file || !preview) return
    const generation = requestGeneration.current
    setLoading(true); setError(null); setReport(null); setStep('audit'); startProgress()
    const form = new FormData(); form.append('configuration', file)
    if (!automaticWan) selectedWans.forEach((wan) => form.append('selected_wans', wan))
    const typedScopes = automaticWan
      ? [{ name: 'automatic', kind: 'automatic' as WanSelectionKind }]
      : selectedWans.map((wan) => ({ name: wan, kind: selectedWanKinds[wan] ?? 'interface' as WanSelectionKind }))
    form.append('selected_wan_scopes', JSON.stringify(typedScopes))
    if (client) form.append('client', client); if (site) form.append('site', site); if (serialNumber) form.append('serial_number', serialNumber); if (uptime) form.append('uptime', uptime); if (unmatchedRules) form.append('unmatched_rules', unmatchedRules); if (operatorComment) form.append('context_comment', operatorComment); if (operator) form.append('operator', operator)
    if (ha) form.append('ha_context', ha); if (mpls) form.append('mpls_context', mpls)
    if (utmLicense) {
      form.append('utm_license', utmLicense)
      form.append('utm_license_status', utmLicense === 'true' ? 'active' : 'inactive')
      form.append('utm_license_manual', String(utmLicenseManual))
      if (utmLicenseExpiration) form.append('utm_license_expiration', utmLicenseExpiration)
      if (utmLicenseProvenance) form.append('utm_license_provenance', utmLicenseProvenance)
    }
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
    setStep('upload'); setFile(null); setPreview(null); setReport(null); setSelectedWans([]); setSelectedWanKinds({}); setAutomaticWan(false); setError(null); setLoading(false); setPreviewing(false)
    setClient(''); setSite(''); setSerialNumber(''); setUptime(''); setUnmatchedRules(''); setOperatorComment(''); setOperator(''); setHa(''); setMpls(''); setUtmLicense(''); setUtmLicenseExpiration(''); setUtmLicenseProvenance(''); setUtmLicenseManual(true); setFilter('ALL')
    if (fileInput.current) fileInput.current.value = ''
  }
  const ordered = useMemo(() => [...(report?.findings ?? [])].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]), [report])
  const visible = filter === 'ALL' ? ordered : ordered.filter((finding) => finding.status === filter)
  const count = (status: AuditStatus) => ordered.filter((finding) => finding.status === status).length
  const severityCount = (severity: string) => ordered.filter((finding) => finding.severity?.toLowerCase() === severity).length
  const wanOptions = useMemo(() => preview ? buildWanOptions(preview) : [], [preview])

  return <div className="app-shell">
    <header className="hero"><img className="hero-image" src={pantherImage} alt="Panthère Vysion" /><div className="hero-content"><p className="eyebrow">SNS Security · usage interne</p><h1>Vysion <span>v2.2.0-dev</span></h1><p>Audit de configuration FortiGate</p></div></header>
    <main>
      <StepNavigation currentStep={step} />
      <input ref={fileInput} className="visually-hidden" aria-label="Configuration FortiGate" id="configuration" name="configuration" type="file" accept=".conf,.txt,text/plain" onChange={(event) => void selectFile(event.target.files?.[0] ?? null)} />
      {step === 'upload' && <section className="panel upload-panel"><div><p className="section-kicker">Étape 1</p><h2>Inspecter une configuration</h2><p>Le fichier est analysé en mémoire, sans persistance lors de la prévisualisation.</p></div><div className="upload-stack"><label className="upload-control" htmlFor="configuration"><strong>{previewing ? 'Inspection en cours…' : 'Sélectionner un fichier .conf'}</strong><span>{file?.name ?? 'Aucun fichier sélectionné'}</span></label>{file && preview && <button className="primary resume-button" type="button" onClick={() => setStep('context')}>Continuer vers le contexte</button>}</div></section>}
      {error && <p role="alert" className="error">{error}</p>}
      {preview && step === 'context' && <form onSubmit={submit} className="workflow">
        <section className="panel equipment" aria-label="Informations équipement"><div className="section-heading"><div><p className="section-kicker">Étape 2</p><h2>Équipement et contexte</h2></div><span className="safe-badge">Preview sûre</span></div>
          <dl className="device-grid"><div><dt>Hostname</dt><dd>{display(preview.hostname)}</dd></div><div><dt>Modèle</dt><dd>{display(preview.model)}</dd></div><div><dt>Version</dt><dd>FortiOS {display(preview.firmware_version)}</dd></div></dl>
          <details className="technical-details"><summary>Détails techniques inspectés</summary><dl><div><dt>Interfaces détectées</dt><dd>{preview.interfaces.length}</dd></div><div><dt>Zones</dt><dd>{preview.zones.map((zone) => zone.name).join(', ') || 'Aucune'}</dd></div><div><dt>SD-WAN</dt><dd>{preview.sdwan_zones.map((zone) => zone.name).join(', ') || 'Non détecté'}</dd></div><div><dt>Numéro de série détecté</dt><dd>{display(preview.serial_number)}</dd></div></dl></details>
          <div className="context-form"><label>Client<input value={client} onChange={(event) => setClient(event.target.value)} placeholder="Non renseigné" /></label><label>Site<input value={site} onChange={(event) => setSite(event.target.value)} placeholder="Non renseigné" /></label><label>Numéro de série<input value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)} placeholder="Saisi manuellement si absent" /></label><label>Uptime<input value={uptime} onChange={(event) => setUptime(event.target.value)} placeholder="Non renseigné" /></label><label>Règles sans match<input aria-label="Règles sans match" type="number" min={0} step={1} value={unmatchedRules} onChange={(event) => setUnmatchedRules(event.target.value)} placeholder="Optionnel — Hit Count ≤ 0" /><small>Observation opérateur issue des statistiques runtime, absente du backup.</small></label><label>Commentaire contexte<textarea aria-label="Commentaire contexte" rows={3} value={operatorComment} onChange={(event) => setOperatorComment(event.target.value)} placeholder="Contexte HA, MPLS/L2L, licence ou réserve métier…" /></label><label>Opérateur<input value={operator} onChange={(event) => setOperator(event.target.value)} placeholder="Opérateur télécom" /></label><TriStateField label="HA" value={ha} onChange={setHa} /><TriStateField label="MPLS" value={mpls} onChange={setMpls} /><TriStateField label="Licence UTM" value={utmLicense} onChange={setUtmLicense} /><label>Date fin licence UTM<input aria-label="Date fin licence UTM" type="date" value={utmLicenseExpiration} onChange={(event) => setUtmLicenseExpiration(event.target.value)} /></label><label>Provenance licence UTM<input aria-label="Provenance licence UTM" value={utmLicenseProvenance} onChange={(event) => setUtmLicenseProvenance(event.target.value)} placeholder="FortiManager, portail, manuel…" /></label><label className="checkbox-field"><input type="checkbox" checked={utmLicenseManual} onChange={(event) => setUtmLicenseManual(event.target.checked)} />Saisie manuelle de la licence</label></div>
          <div className="actions guided-actions"><button className="secondary" type="button" onClick={() => setStep('upload')}>Retour à l’upload</button><button className="primary" type="button" onClick={() => setStep('wan')}>Continuer vers la sélection WAN</button></div>
        </section>
      </form>}
      {preview && step === 'wan' && <section className="panel workflow" aria-label="Sélection WAN"><div className="section-heading"><div><p className="section-kicker">Étape 3</p><h2>Sélection WAN</h2></div><span className="safe-badge">Options envoyables</span></div><p className="intro">Sélectionnez une interface, une zone ou un périmètre SD-WAN. La relation Interface → Zone → Flux → Politique reste conservée dans le rapport.</p>
        <fieldset className="wan-selection"><legend>Options WAN envoyables</legend><div className="automatic-selection"><button type="button" className={automaticWan ? 'primary' : 'secondary'} aria-pressed={automaticWan} onClick={() => { const next = !automaticWan; setAutomaticWan(next); if (next) { setSelectedWans([]); setSelectedWanKinds({}) } }}>{automaticWan ? 'Association automatique activée' : 'Sélectionner automatiquement les WAN détectées'}</button><small>Les interfaces WAN et leurs zones associées sont résolues côté serveur.</small></div><div className="wan-grid">{wanOptions.map((option) => <label key={`${option.name}:${option.scopes.join('|')}`}><input aria-label={`WAN ${option.name}`} type="checkbox" checked={!automaticWan && selectedWans.includes(option.name)} onChange={() => { setAutomaticWan(false); setSelectedWans((current) => current.includes(option.name) ? current.filter((name) => name !== option.name) : [...current, option.name]); setSelectedWanKinds((current) => { const next = { ...current }; if (selectedWans.includes(option.name)) delete next[option.name]; else next[option.name] = option.defaultKind; return next }) }} /><span><strong>{option.name}</strong><small>{option.kinds.join(' · ')}{option.interfaces.length ? ` · ${option.interfaces.join(', ')}` : ''}</small>{option.scopes.length > 1 && <select aria-label={`Type WAN ${option.name}`} value={selectedWanKinds[option.name] ?? option.defaultKind} onChange={(event) => { setAutomaticWan(false); setSelectedWanKinds((current) => ({ ...current, [option.name]: event.target.value as WanSelectionKind })) }}><option value="interface">Interface</option><option value="zone">Zone</option><option value="sdwan">SD-WAN</option></select>}</span></label>)}</div>{wanOptions.length === 0 && <p className="empty-state">Aucune option nommée et envoyable n’a été fournie par l’inspection.</p>}</fieldset>
        <div className="actions"><button className="secondary" type="button" onClick={() => setStep('context')}>Retour au contexte</button><button className="primary" type="button" onClick={() => setStep('options')}>Continuer vers les options d’audit</button></div>
      </section>}
      {preview && step === 'options' && <form onSubmit={submit} className="workflow"><section className="panel" aria-label="Options d’audit"><div className="section-heading"><div><p className="section-kicker">Étape 4</p><h2>Options d’audit</h2></div><span className="safe-badge">Contexte prêt</span></div><p className="intro">Relisez les informations opérateur avant de lancer l’audit. Les valeurs « Non renseigné » restent inconnues et ne sont pas envoyées.</p><dl className="option-review"><div><dt>WAN sélectionnées</dt><dd>{display(automaticWan ? 'Association automatique' : selectedWans.join(', '))}</dd></div><div><dt>Client / site</dt><dd>{display([client, site].filter(Boolean).join(' · '))}</dd></div><div><dt>HA</dt><dd>{display(ha === '' ? null : ha === 'true')}</dd></div><div><dt>MPLS / L2L</dt><dd>{display(mpls === '' ? null : mpls === 'true')}</dd></div><div><dt>Licence UTM</dt><dd>{display(utmLicense === '' ? null : utmLicense === 'true' ? 'active' : 'inactive')} · {display(utmLicenseExpiration)}</dd></div><div><dt>Provenance</dt><dd>{display(utmLicenseProvenance || 'operator-form · manual-selection')}</dd></div></dl><div className="actions"><button className="secondary" type="button" onClick={() => setStep('wan')}>Retour à la sélection WAN</button><button className="primary" type="submit" disabled={loading}>Lancer l’audit</button></div></section></form>}
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
