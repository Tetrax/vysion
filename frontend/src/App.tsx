import { FormEvent, useMemo, useRef, useState } from 'react'
import pantherImage from './assets/panther.jpg'
import { VYSION_VERSION } from './buildInfo'
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
type EquipmentInventory = {
  hostname?: string | null; model?: string | null; firmware_version?: string | null; serial_number?: string | null
  interface_names?: string[]; zone_names?: string[]; sdwan_zone_names?: string[]; interface_zone_relations?: string[]
  policy_count: number; policy_enabled_count: number; policy_disabled_count: number; policy_status_unknown_count: number
  service_object_count: number; vip_count: number; security_profile_count: number; ipsec_tunnel_count: number
  ssl_vpn_configured: boolean; ha_configured: boolean
}
type AuditReport = { schema_version?: number; report_id: string; expires_at: string; context?: AuditContext; equipment?: EquipmentInventory; fortiguard: { status: string; detail: string }; findings: Finding[] }
type PreviewInterface = { name: string; role?: string | null; zone?: string | null }
type PreviewZone = { name: string; interfaces: string[] }
type Preview = { hostname?: string | null; model?: string | null; firmware_version?: string | null; serial_number?: string | null; interfaces: PreviewInterface[]; zones: PreviewZone[]; wan_relations?: { interface: string; zone: string }[]; sdwan_zones: PreviewZone[] }
type ApiErrorDetail = { detail?: string | Array<{ msg?: string }> }
type Filter = 'ALL' | AuditStatus

type WanSelectionKind = 'interface' | 'zone' | 'sdwan' | 'automatic'
type WanOption = { name: string; kinds: string[]; scopes: WanSelectionKind[]; interfaces: string[]; defaultKind: WanSelectionKind }

const STATUS_ORDER: Record<AuditStatus, number> = { FAIL: 0, ERROR: 0, UNKNOWN: 1, PASS: 2, NOT_APPLICABLE: 3 }
const DOMAIN_LABELS: Record<string, string> = { system: 'Système', administration: 'Administration / Identity', identity: 'Administration / Identity', iam: 'Administration / Identity', network: 'Réseau', firewall: 'Firewall', vpn: 'VPN', utm: 'UTM', wifi: 'Wi-Fi' }
const DOMAIN_ORDER = ['Système', 'Administration / Identity', 'Réseau', 'Firewall', 'VPN', 'UTM', 'Wi-Fi', 'Autre']

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

function ContextSummary({ context }: { context: AuditContext }) {
  const license = context.utm_license_details
  const licenseStatus = license?.status ?? (context.utm_license === true ? 'active' : context.utm_license === false ? 'inactive' : null)
  const wanSummary = context.wan_selections?.map((selection) => `${selection.name} (${selection.kind})`).join(', ') ?? context.selected_wans?.join(', ')
  return <section className="context-summary" aria-label="Contexte de l’audit"><h3>Contexte saisi</h3><dl>
    <div><dt>Client</dt><dd>{display(context.client)}</dd></div><div><dt>Site</dt><dd>{display(context.site)}</dd></div>
    <div><dt>Numéro de série</dt><dd>{display(context.serial_number)}</dd></div><div><dt>WAN sélectionnées</dt><dd>{display(wanSummary)}</dd></div>
    <div><dt>HA</dt><dd>{display(context.ha)}</dd></div><div><dt>MPLS / L2L</dt><dd>{display(context.mpls)}</dd></div>
    <div><dt>Licence UTM</dt><dd>{display(licenseStatus)}</dd></div><div><dt>Uptime</dt><dd>{display(context.uptime)}</dd></div>
    <div><dt>Règles sans match</dt><dd>{display(context.rule_match_statistics?.unmatched_rules)}</dd></div>
    <div><dt>Commentaire contexte</dt><dd>{display(context.operator_comment)}</dd></div>
  </dl></section>
}

function EquipmentInventorySummary({ equipment }: { equipment: EquipmentInventory }) {
  const list = (values?: string[]) => values?.join(', ') || 'Aucune'
  return <section className="context-summary" aria-label="Inventaire de configuration"><h3>Inventaire de configuration</h3><dl>
    <div><dt>Hostname</dt><dd>{display(equipment.hostname)}</dd></div><div><dt>Modèle</dt><dd>{display(equipment.model)}</dd></div>
    <div><dt>Version FortiOS</dt><dd>{display(equipment.firmware_version)}</dd></div><div><dt>Numéro de série</dt><dd>{display(equipment.serial_number)}</dd></div>
    <div><dt>Interfaces projetées</dt><dd>{list(equipment.interface_names)}</dd></div><div><dt>Zones</dt><dd>{list(equipment.zone_names)}</dd></div>
    <div><dt>Zones SD-WAN</dt><dd>{list(equipment.sdwan_zone_names)}</dd></div><div><dt>Relations interface → zone</dt><dd>{list(equipment.interface_zone_relations)}</dd></div>
    <div><dt>Règles firewall</dt><dd>{equipment.policy_count}</dd></div><div><dt>Actives explicites</dt><dd>{equipment.policy_enabled_count}</dd></div>
    <div><dt>Désactivées explicites</dt><dd>{equipment.policy_disabled_count}</dd></div><div><dt>Statut inconnu</dt><dd>{equipment.policy_status_unknown_count}</dd></div>
    <div><dt>Objets service</dt><dd>{equipment.service_object_count}</dd></div><div><dt>VIP et virtual servers</dt><dd>{equipment.vip_count}</dd></div>
    <div><dt>Profils de sécurité</dt><dd>{equipment.security_profile_count}</dd></div><div><dt>Tunnels IPsec</dt><dd>{equipment.ipsec_tunnel_count}</dd></div>
    <div><dt>SSL-VPN configuré</dt><dd>{display(equipment.ssl_vpn_configured)}</dd></div><div><dt>HA configuré</dt><dd>{display(equipment.ha_configured)}</dd></div>
  </dl><p className="intro">Volumes issus de la configuration projetée ; aucune métrique runtime n'est inventée.</p></section>
}

function formatEvidence(item: EvidenceValue): string {
  if (typeof item === 'string') return item
  const details = [item.section, item.entry, item.directive, item.tokens?.join(' '), item.line !== null && item.line !== undefined ? `ligne ${item.line}` : null, item.certainty, item.defaulted ? 'valeur par défaut' : null].filter(Boolean)
  return details.join(' · ') || 'Preuve structurée'
}
function evidenceKey(item: EvidenceItem): string {
  return JSON.stringify([item.section, item.entry, item.directive, item.tokens, item.line, item.certainty, item.defaulted])
}
function Evidence({ finding }: { finding: Finding }) {
  const [allEvidence, setAllEvidence] = useState(false)
  const structuredItems = finding.evidence_items ?? []
  const structuredKeys = new Set(structuredItems.map(evidenceKey))
  const legacyValues = (finding.evidence ?? []).filter((item) => typeof item === 'string' || !structuredKeys.has(evidenceKey(item))).map(formatEvidence)
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
    <p className="finding-domain">{domainOf(finding)}</p>
    <p className="message">{finding.message}</p><p className="risk-line"><strong>Risque :</strong> {riskSummary(finding.risk)}</p>
    <button className="details-button" type="button" aria-expanded={open} aria-controls={`details-${finding.control_id}`} onClick={() => setOpen(!open)}>{open ? 'Masquer les détails' : 'Voir les détails'}</button>
    {open && <div id={`details-${finding.control_id}`} className="finding-details">
      <dl><div><dt>Contrôle</dt><dd>{display(finding.control_id)}</dd></div><div><dt>Catégorie</dt><dd>{display(finding.category)}</dd></div><div><dt>Priorité</dt><dd>{display(finding.priority)}</dd></div><div><dt>Applicabilité</dt><dd>{display(finding.applicability)}</dd></div><div><dt>Approbation client</dt><dd>{display(finding.customer_approval)}</dd></div></dl>
      <h4>Preuves</h4><Evidence finding={finding} />
      <h4>Objets affectés</h4>{shown.length ? <ul className="detail-list">{shown.map((item, index) => <li key={`${item.object_type}-${item.name}-${index}`}>{item.object_type ?? 'unknown'} · {item.name}</li>)}</ul> : <p>Non renseigné</p>}
      {objects.length > 3 && <button type="button" className="text-button" aria-expanded={allObjects} onClick={() => setAllObjects(!allObjects)}>{allObjects ? 'Réduire la liste' : `Afficher les ${objects.length} éléments`}</button>}
      {typeof finding.risk === 'object' && finding.risk && <><h4>Analyse du risque</h4><dl><div><dt>Impact</dt><dd>{display(finding.risk.impact)}</dd></div><div><dt>Vraisemblance</dt><dd>{display(finding.risk.likelihood)}</dd></div><div><dt>Traitement</dt><dd>{display(finding.risk.treatment)}</dd></div></dl></>}
      <h4>Recommandation</h4><p>{display(finding.recommendation)}</p><h4>Remédiation</h4><p>{display(finding.remediation)}</p>
    </div>}
  </article>
}
function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) { return <div className={`stat ${tone ?? ''}`}><span>{label}</span><strong>{value}</strong></div> }
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
  const [licenseEndDate, setLicenseEndDate] = useState('')
  const [uptime, setUptime] = useState('')
  const [unmatchedRules, setUnmatchedRules] = useState('0')
  const [operatorComment, setOperatorComment] = useState('')
  const [ha, setHa] = useState<TriState>('')
  const [mpls, setMpls] = useState<TriState>('')
  const [utmLicense, setUtmLicense] = useState<TriState>('')
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
    stopProgress(); setProgress(0)
    setFile(selected); setPreview(null); setReport(null); setError(null); setSelectedWans([]); setSelectedWanKinds({}); setAutomaticWan(false); setLoading(false); setStep('upload')
    setClient(''); setSite(''); setSerialNumber(''); setLicenseEndDate(''); setUptime(''); setUnmatchedRules('0'); setOperatorComment(''); setHa(''); setMpls(''); setUtmLicense('')
    if (!selected) return
    setPreviewing(true)
    const form = new FormData(); form.append('configuration', selected)
    try {
      const response = await fetch('/api/audits/preview', { method: 'POST', body: form })
      if (!response.ok) throw await responseError(response, 'Inspection')
      const inspected = (await response.json()) as Preview
      if (generation !== requestGeneration.current) return
      setPreview(inspected); setSerialNumber(inspected.serial_number ?? '')
      const defaults = buildWanOptions(inspected).filter((option) => option.kinds.includes('Interface WAN'))
      setSelectedWans(defaults.map((option) => option.name)); setSelectedWanKinds(Object.fromEntries(defaults.map((option) => [option.name, option.defaultKind]))); setAutomaticWan(false); setStep('context')
    } catch (reason) { if (generation === requestGeneration.current) setError(reason instanceof Error ? reason.message : 'Inspection impossible') }
    finally { if (generation === requestGeneration.current) setPreviewing(false) }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!file || !preview) return
    const generation = requestGeneration.current
    setLoading(true); setError(null); setReport(null); setStep('audit'); startProgress()
    const form = new FormData(); form.append('configuration', file)
    if (!automaticWan) selectedWans.forEach((wan) => form.append('selected_wans', wan))
    const typedScopes = automaticWan ? [{ name: 'automatic', kind: 'automatic' as WanSelectionKind }] : selectedWans.map((wan) => ({ name: wan, kind: selectedWanKinds[wan] ?? 'interface' as WanSelectionKind }))
    form.append('selected_wan_scopes', JSON.stringify(typedScopes))
    if (client) form.append('client', client); if (site) form.append('site', site); if (serialNumber) form.append('serial_number', serialNumber); if (licenseEndDate) form.append('utm_license_expiration', licenseEndDate); if (uptime) form.append('uptime', uptime); if (unmatchedRules) form.append('unmatched_rules', unmatchedRules); if (operatorComment) form.append('context_comment', operatorComment)
    if (ha) form.append('ha_context', ha); if (mpls) form.append('mpls_context', mpls)
    if (utmLicense) { form.append('utm_license', utmLicense); form.append('utm_license_status', utmLicense === 'true' ? 'active' : 'inactive'); form.append('utm_license_manual', 'true') }
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
    requestGeneration.current += 1; stopProgress(); setProgress(0)
    setStep('upload'); setFile(null); setPreview(null); setReport(null); setSelectedWans([]); setSelectedWanKinds({}); setAutomaticWan(false); setError(null); setLoading(false); setPreviewing(false)
    setClient(''); setSite(''); setSerialNumber(''); setLicenseEndDate(''); setUptime(''); setUnmatchedRules('0'); setOperatorComment(''); setHa(''); setMpls(''); setUtmLicense(''); setFilter('ALL')
    if (fileInput.current) fileInput.current.value = ''
  }

  const ordered = useMemo(() => [...(report?.findings ?? [])].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]), [report])
  const visible = filter === 'ALL' ? ordered : ordered.filter((finding) => finding.status === filter)
  const count = (status: AuditStatus) => ordered.filter((finding) => finding.status === status).length
  const severityCount = (severity: string) => ordered.filter((finding) => finding.severity?.toLowerCase() === severity).length
  function toggleWan(name: string, kind: WanSelectionKind) {
    const selected = selectedWans.includes(name)
    setAutomaticWan(false)
    setSelectedWans((current) => selected ? current.filter((item) => item !== name) : [...current, name])
    setSelectedWanKinds((current) => {
      const next = { ...current }
      if (selected) delete next[name]
      else next[name] = kind
      return next
    })
  }

  const nonConform = ordered.filter((finding) => finding.status !== 'PASS')

  return <div className="app-shell">
    <header className="hero">
      <img className="hero-image" src={pantherImage} alt="Panthère Vysion" />
      <div className="hero-content">
        <h1 aria-label={`Vysion ${VYSION_VERSION}`}>Vysion</h1>
        <p>Audit Configuration FortiGate</p>
      </div>
    </header>

    <main className="main">
      <input ref={fileInput} className="visually-hidden" aria-label="Configuration FortiGate" id="configuration" name="configuration" type="file" accept=".conf,.txt,text/plain" onChange={(event) => void selectFile(event.target.files?.[0] ?? null)} />

      {step === 'upload' && <section className="step">
        <h2 aria-label="Inspecter une configuration">Etape 1 : Upload Configuration</h2>
        <div className="upload-area">
          <label htmlFor="configuration" className="upload-button">{previewing ? 'Processing...' : 'Select FortiGate .conf file'}</label>
          {!file && <span className="visually-hidden">Aucun fichier sélectionné</span>}
          {file && <p className="file-name">Selected: <span>{file.name}</span></p>}
          {file && preview && <button className="visually-hidden" type="button" aria-label="Continuer vers le contexte" onClick={() => setStep('context')}>Continue</button>}
        </div>
      </section>}

      {error && <div role="alert" className="error">{error}</div>}

      {preview && step === 'context' && <form onSubmit={submit}>
        <section className="step" aria-label="Informations équipement">
          <h2 aria-label="Équipement et contexte">Etape 2 : Renseignements</h2>
          <div className="info-box">
            <p><strong>Hostname:</strong> <span>{display(preview.hostname)}</span> | <strong>Version:</strong> <span>{display(preview.firmware_version)}</span> | <strong>Model:</strong> <span>{display(preview.model)}</span><span className="visually-hidden">FortiOS {display(preview.firmware_version)}</span></p>
          </div>

          <div className="visually-hidden">
            <label><input aria-label="HA présent" type="checkbox" checked={ha === 'true'} onChange={(event) => setHa(event.target.checked ? 'true' : '')} /> HA présent</label>
            <label><input aria-label="MPLS / L2L présent" type="checkbox" checked={mpls === 'true'} onChange={(event) => setMpls(event.target.checked ? 'true' : '')} /> MPLS / L2L présent</label>
            <label><input aria-label="Licence UTM active" type="checkbox" checked={utmLicense === 'true'} onChange={(event) => setUtmLicense(event.target.checked ? 'true' : '')} /> Licence UTM active</label>
          </div>

          <div className="options-form">
            <label className="checkbox-item"><span>Nom du client</span><input aria-label="Client" type="text" value={client} onChange={(event) => setClient(event.target.value)} className="text-input" /></label>
            <label className="checkbox-item"><span>Nom du site</span><input aria-label="Site" type="text" value={site} onChange={(event) => setSite(event.target.value)} className="text-input" /></label>
            <label className="checkbox-item"><span>Numéro de série</span><input type="text" value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)} className="text-input" /></label>
            <label className="checkbox-item"><span>Date de fin de licence</span><input type="date" value={licenseEndDate} onChange={(event) => setLicenseEndDate(event.target.value)} className="date-input" /></label>
            <label className="checkbox-item"><span>System Uptime</span><input aria-label="Uptime" type="date" value={uptime} onChange={(event) => setUptime(event.target.value)} className="date-input" /></label>
          </div>

          <div className="button-group">
            <button onClick={() => setStep('upload')} className="button secondary" type="button" aria-label="Retour à l’upload">Back</button>
            <button onClick={() => setStep('wan')} className="button primary" type="button" aria-label="Continuer vers la sélection WAN">Continue</button>
          </div>
          <details className="v2-secondary"><summary>Détails techniques inspectés</summary><dl className="technical-grid">
            <div><dt>Interfaces détectées</dt><dd>{preview.interfaces.length}</dd></div>
            <div><dt>Zones</dt><dd>{preview.zones.map((zone) => zone.name).join(', ') || 'Aucune'}</dd></div>
            <div><dt>SD-WAN</dt><dd>{preview.sdwan_zones.map((zone) => zone.name).join(', ') || 'Non détecté'}</dd></div>
            <div><dt>Relations WAN</dt><dd>{preview.wan_relations?.map((relation) => `${relation.interface} → ${relation.zone}`).join(', ') || 'Non renseignées'}</dd></div>
          </dl></details>
          <details className="v2-secondary"><summary>Informations complémentaires (optionnelles)</summary><div className="v2-secondary-body">
            <label>Règles sans match<input aria-label="Règles sans match" type="number" min={0} step={1} value={unmatchedRules} onChange={(event) => setUnmatchedRules(event.target.value)} /><small>Observation issue des statistiques runtime, absente du backup.</small></label>
            <label>Commentaire contexte<textarea aria-label="Commentaire contexte" rows={3} value={operatorComment} onChange={(event) => setOperatorComment(event.target.value)} placeholder="Contexte ou réserve métier…" /></label>
          </div></details>
        </section>
      </form>}

      {preview && step === 'wan' && <section className="step wan-step" aria-label="Sélection WAN">
        <h2 aria-label="Sélection WAN">Etape 3 : Sélection des WAN Interfaces</h2>

        <fieldset className="selection-section" aria-label="Interfaces WAN">
          <h3>Interfaces WAN à sélectionner</h3>
          <div className="checkbox-list interfaces-list">
            {preview.interfaces.filter((item) => item.name.trim()).map((item) => <label key={`interface-${item.name}`} className="checkbox-item">
              <input aria-label={`WAN ${item.name}`} type="checkbox" checked={!automaticWan && selectedWans.includes(item.name)} onChange={() => toggleWan(item.name, 'interface')} />
              <span>{item.name}</span>
            </label>)}
            {preview.interfaces.length === 0 && <p className="empty-state">Aucune interface détectée.</p>}
          </div>
        </fieldset>

        <fieldset className="selection-section" aria-label="Zones">
          <h3>Zones WAN à sélectionner</h3>
          <div className="checkbox-list zones-list">
            {preview.zones.filter((zone) => zone.name.trim()).map((zone) => <label key={`zone-${zone.name}`} className="checkbox-item">
              <input aria-label={`WAN ${preview.interfaces.some((item) => item.name === zone.name) ? `zone ${zone.name}` : zone.name}`} type="checkbox" checked={!automaticWan && selectedWans.includes(zone.name)} onChange={() => toggleWan(zone.name, 'zone')} />
              <span>Zone: {zone.name} ({zone.interfaces.join(', ')})</span>
            </label>)}
            {preview.zones.length === 0 && <p className="empty-state">Aucune zone WAN détectée.</p>}
          </div>
        </fieldset>

        <fieldset className="selection-section" aria-label="SD-WAN">
          <h3>SD-WAN Zones</h3>
          <div className="checkbox-list sdwan-list">
            {preview.sdwan_zones.filter((zone) => zone.name.trim()).map((zone) => <label key={`sdwan-${zone.name}`} className="checkbox-item">
              <input aria-label={`WAN ${preview.interfaces.some((item) => item.name === zone.name) || preview.zones.some((item) => item.name === zone.name) ? `sdwan ${zone.name}` : zone.name}`} type="checkbox" checked={!automaticWan && selectedWans.includes(zone.name)} onChange={() => toggleWan(zone.name, 'sdwan')} />
              <span>SD-WAN Zone: {zone.name} ({zone.interfaces.join(', ')})</span>
            </label>)}
            {preview.sdwan_zones.length === 0 && <p className="empty-state">Aucune zone SD-WAN détectée.</p>}
          </div>
        </fieldset>

        <div className="visually-hidden" aria-label="Types WAN V2">{buildWanOptions(preview).filter((option) => option.scopes.length > 1).map((option) => <label key={`wan-type-${option.name}`}>Type WAN {option.name}<select aria-label={`Type WAN ${option.name}`} value={selectedWanKinds[option.name] ?? option.defaultKind} onChange={(event) => setSelectedWanKinds((current) => ({ ...current, [option.name]: event.target.value as WanSelectionKind }))}><option value="interface">Interface</option><option value="zone">Zone</option><option value="sdwan">SD-WAN</option></select></label>)}</div>
        <div className="button-group">
          <button className="button secondary" type="button" onClick={() => setStep('context')} aria-label="Retour au contexte">Back</button>
          <button className="button primary" type="button" onClick={() => setStep('options')} aria-label="Continuer vers les options d’audit">Continue</button>
        </div>
        <details className="v2-secondary"><summary>Association automatique V2</summary><div className="v2-secondary-body"><button type="button" className="button secondary" aria-pressed={automaticWan} onClick={() => { const next = !automaticWan; setAutomaticWan(next); if (next) { setSelectedWans([]); setSelectedWanKinds({}) } }}>{automaticWan ? 'Association automatique activée' : 'Sélectionner automatiquement les WAN détectées'}</button><small>Le serveur résout ensuite les relations interface → zone → flux.</small></div></details>
      </section>}

      {preview && step === 'options' && <form onSubmit={submit}>
        <section className="step" aria-label="Options d’audit">
          <h2 aria-label="Options d’audit">Etape 4 : Options d'audit</h2>
          <div className="options-form">
            <label className="checkbox-item"><input aria-label="Licence UTM active" type="checkbox" checked={utmLicense === 'true'} onChange={(event) => setUtmLicense(event.target.checked ? 'true' : '')} /><span>Licence UTM Valide</span></label>
            <label className="checkbox-item"><input aria-label="MPLS / L2L présent" type="checkbox" checked={mpls === 'true'} onChange={(event) => setMpls(event.target.checked ? 'true' : '')} /><span>Lien MPLS ou L2L</span></label>
            <label className="checkbox-item"><input aria-label="HA présent" type="checkbox" checked={ha === 'true'} onChange={(event) => setHa(event.target.checked ? 'true' : '')} /><span>Redondance câblage HA</span></label>
            <label className="checkbox-item number-item"><div><span>Nombre de règles sans match</span><div className="field-hint">Filtrez sur <strong>'&lt;=0'</strong> sur la colonne <strong>"Hit Count"</strong> des Firewall policies</div></div><input aria-label="Règles sans match options" type="number" min={0} step={1} value={unmatchedRules} onChange={(event) => setUnmatchedRules(event.target.value)} /></label>
          </div>
          <div className="button-group">
            <button onClick={() => setStep('wan')} className="button secondary" type="button" aria-label="Retour à la sélection WAN">Back</button>
            <button className="button primary" type="submit" disabled={loading} aria-label="Lancer l’audit">Run Audit</button>
          </div>
        </section>
      </form>}

      {preview && step === 'audit' && <section className="step audit-panel" aria-live="polite">
        <h2>Running Audit...</h2>
        <p role="status" className="visually-hidden">Audit en cours : analyse de la configuration et génération du rapport…</p>
        <div className="progress-container"><div className="progress-bar" role="progressbar" aria-label="Progression de l’audit" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress} aria-valuetext={`${progress}%`}><div className="progress-fill" style={{ width: `${progress}%` }} /></div><p className="progress-text" aria-live="polite">{progress}%</p></div>
      </section>}

      {report && step === 'results' && <section className="step results" aria-live="polite">
        <h2 aria-label="Synthèse et résultats">Audit Complete</h2>
        <div className="info-box" aria-label="Synthèse de l’audit">
          <p><strong>Hostname:</strong> <span>{display(report.equipment?.hostname)}</span> | <strong>Version:</strong> <span>{display(report.equipment?.firmware_version)}</span> | <strong>Model:</strong> <span>{display(report.equipment?.model)}</span></p>
          <p><strong>Total Checks:</strong> {ordered.length}</p>
        </div>

        {nonConform.length > 0 ? <div className="reports-section">
          <h3>Check-list de contrôles basiques non conformes</h3>
          <div className="checks-table-wrapper"><table className="checks-table"><thead><tr><th>Contrôle</th><th className="checks-status-col">Statut</th></tr></thead><tbody>
            {nonConform.map((finding) => <tr key={finding.control_id}><td className="checks-name">{finding.title}</td><td className="checks-status"><span className={`status-icon ${finding.status.toLowerCase()}`} aria-label={finding.status}>{finding.status === 'FAIL' ? '✕' : finding.status === 'UNKNOWN' ? '?' : '!'}</span></td></tr>)}
          </tbody></table></div>
        </div> : <div className="reports-section"><h3>Contrôles</h3><div className="info-box">✅ Aucun contrôle non conforme détecté.</div></div>}

        <div className="reports-section"><h3>Download Reports</h3><div className="button-group report-downloads">
          <a href={`/api/reports/${report.report_id}.xlsx`} className="button primary">Download Excel Report</a>
          <a href={`/api/reports/${report.report_id}.docx`} className="button primary">Download Word Report</a>
        </div></div>
        <div className="button-group"><button onClick={resetAudit} className="button secondary" type="button" aria-label="Nouvel audit">Start New Audit</button></div>
        <details className="v2-secondary"><summary>Détails V2 de l’audit</summary><div className="v2-secondary-body">
          <a href={`/api/reports/${report.report_id}.json`} className="button secondary">Download JSON Audit</a>
          {report.schema_version && <p>Schéma {report.schema_version}</p>}
          {(count('UNKNOWN') + count('ERROR') > 0) && <div className="warning-box">Certains contrôles n'ont pas pu être établis. Aucun statut UNKNOWN ou ERROR n'est considéré conforme.</div>}
          {report.context && <ContextSummary context={report.context} />}
          {report.equipment && <EquipmentInventorySummary equipment={report.equipment} />}
          <div className="summary-layout"><div className="stats" aria-label="Synthèse des statuts"><Stat label="TOTAL" value={ordered.length} /><Stat label="FAIL" value={count('FAIL')} tone="fail" /><Stat label="ERROR" value={count('ERROR')} tone="fail" /><Stat label="UNKNOWN" value={count('UNKNOWN')} tone="unknown" /><Stat label="PASS" value={count('PASS')} tone="pass" /><Stat label="N-A" value={count('NOT_APPLICABLE')} tone="na" /></div><div className="stats severity-stats" aria-label="Synthèse des sévérités"><Stat label="Critical" value={severityCount('critical')} /><Stat label="High" value={severityCount('high')} /><Stat label="Medium" value={severityCount('medium')} /><Stat label="Low" value={severityCount('low')} /><Stat label="Info" value={severityCount('info')} /></div></div>
          <div className="domain-summary" aria-label="Synthèse par domaine">{DOMAIN_ORDER.map((domain) => { const items = ordered.filter((finding) => domainOf(finding) === domain); return <div key={domain}><strong>{domain}</strong><span>{items.length} contrôle{items.length > 1 ? 's' : ''}</span><small>{items.length ? items[0].status : '—'}</small></div> })}</div>
          <div className="filters" aria-label="Filtres des résultats">{(['ALL', 'FAIL', 'ERROR', 'UNKNOWN', 'PASS', 'NOT_APPLICABLE'] as Filter[]).map((item) => <button type="button" key={item} className={filter === item ? 'active' : ''} aria-pressed={filter === item} onClick={() => setFilter(item)}>{item === 'ALL' ? 'Tous' : item === 'NOT_APPLICABLE' ? 'N-A' : item}</button>)}</div>
          <div className="finding-grid">{visible.map((finding) => <FindingCard key={finding.control_id} finding={finding} />)}</div>
        </div></details>
      </section>}
    </main>
    <footer className="footer"><p>Vysion</p></footer>
  </div>
}

export default App
