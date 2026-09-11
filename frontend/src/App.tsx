import { FormEvent, useRef, useState } from 'react'
import pantherImage from './assets/panther.jpg'
import { VYSION_VERSION } from './buildInfo'
import './app.css'

type AuditStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR' | 'NOT_APPLICABLE'
type TriState = '' | 'true' | 'false'
type Step = 'upload' | 'context' | 'wan' | 'options' | 'audit' | 'results'
type Finding = { control_id: string; title: string; display_name?: string | null; status: AuditStatus }
type PresentationRow = {
  business_key: string
  order: number
  display_name: string
  relation: string
  classification: string
  presentation_kind: string
  v2_control_ids: string[]
  v2_projection?: string | null
  status?: AuditStatus | null
  result?: string | null
  finding_ids: string[]
}
type Presentation = {
  business_control_count: number
  engine_control_count: number
  split_extra_finding_count: number
  v2_only_control_count: number
  explanation_lines: string[]
  business_rows: PresentationRow[]
  v2_only_rows: PresentationRow[]
  engine_error_rows?: PresentationRow[]
}
type AuditReport = {
  report_id: string
  fortiguard: { status: string; detail: string }
  findings: Finding[]
  presentation?: Presentation | null
}
type PreviewInterface = { name: string; role?: string | null; zone?: string | null }
type PreviewZone = { name: string; interfaces: string[]; proof_state?: string }
type PreviewSdwanMember = { name: string; zones: string[] }
type Preview = {
  hostname?: string | null
  model?: string | null
  firmware_version?: string | null
  serial_number?: string | null
  interfaces: PreviewInterface[]
  zones: PreviewZone[]
  wan_relations?: { interface: string; zone: string }[]
  sdwan_zones: PreviewZone[]
  sdwan_members?: PreviewSdwanMember[]
}
type ApiErrorDetail = { detail?: string | Array<{ msg?: string }> }
type WanSelectionKind = 'interface' | 'zone' | 'sdwan'
type WanScope = { name: string; kind: WanSelectionKind }
type WanOption = { name: string; kinds: string[]; scopes: WanSelectionKind[]; interfaces: string[]; defaultKind: WanSelectionKind }

function buildWanOptions(preview: Preview): WanOption[] {
  const byName = new Map<string, WanOption>()
  function add(name: string, kind: WanSelectionKind, label: string, interfaces: string[], preferred = false) {
    const normalized = name.trim()
    if (!normalized) return
    const key = normalized.toLocaleLowerCase()
    const existing = byName.get(key)
    if (existing) {
      if (!existing.scopes.includes(kind)) {
        existing.scopes.push(kind)
        existing.kinds.push(label)
      }
      existing.interfaces = [...new Set([...existing.interfaces, ...interfaces.filter(Boolean)])]
      if (preferred) existing.defaultKind = kind
      return
    }
    byName.set(key, {
      name: normalized,
      kinds: [label],
      scopes: [kind],
      interfaces: [...new Set(interfaces.filter(Boolean))],
      defaultKind: kind,
    })
  }
  preview.interfaces.forEach((item) => add(item.name, 'interface', item.role === 'wan' ? 'Interface WAN' : 'Interface', [], item.role === 'wan'))
  preview.sdwan_members?.forEach((member) => add(member.name, 'interface', 'Membre SD-WAN', [], true))
  preview.zones.forEach((zone) => add(zone.name, 'zone', 'Zone', zone.interfaces))
  preview.sdwan_zones.forEach((zone) => add(zone.name, 'sdwan', 'SD-WAN', zone.interfaces))
  return [...byName.values()]
}

function display(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Non renseigné'
  if (typeof value === 'boolean') return value ? 'Oui' : 'Non'
  return String(value)
}

async function responseError(response: Response, action: string): Promise<Error> {
  try {
    const payload = (await response.json()) as ApiErrorDetail
    const detail = typeof payload.detail === 'string'
      ? payload.detail
      : payload.detail?.map((item) => item.msg).filter(Boolean).join(' · ')
    if (detail) return new Error(`${action} refusé : ${detail}`)
  } catch { /* status fallback */ }
  return new Error(`${action} refusé (HTTP ${response.status})`)
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
  const [licenseEndDate, setLicenseEndDate] = useState('')
  const [uptime, setUptime] = useState('')
  const [unmatchedRules, setUnmatchedRules] = useState('0')
  // The V1 options are boolean answers: an unchecked box is an explicit
  // negative, not an omitted/unknown answer. Keep the same visual control
  // while preserving that distinction in the submitted context.
  const [ha, setHa] = useState<TriState>('false')
  const [mpls, setMpls] = useState<TriState>('false')
  const [utmLicense, setUtmLicense] = useState<TriState>('false')
  const [selectedWanScopes, setSelectedWanScopes] = useState<WanScope[]>([])
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
    setFile(selected)
    setPreview(null)
    setReport(null)
    setError(null)
    setSelectedWanScopes([])
    setLoading(false)
    setStep('upload')
    setClient('')
    setSite('')
    setSerialNumber('')
    setLicenseEndDate('')
    setUptime('')
    setUnmatchedRules('0')
    setHa('false')
    setMpls('false')
    setUtmLicense('false')
    if (!selected) return

    setPreviewing(true)
    const form = new FormData()
    form.append('configuration', selected)
    try {
      const response = await fetch('/api/audits/preview', { method: 'POST', body: form })
      if (!response.ok) throw await responseError(response, 'Inspection')
      const inspected = (await response.json()) as Preview
      if (generation !== requestGeneration.current) return
      setPreview(inspected)
      const defaults = buildWanOptions(inspected).filter((option) => (
        option.scopes.includes('interface')
        && (option.kinds.includes('Interface WAN') || option.kinds.includes('Membre SD-WAN'))
      ))
      setSelectedWanScopes(defaults.map((option) => ({ name: option.name, kind: 'interface' })))
      setSerialNumber(inspected.serial_number ?? '')
      setStep('context')
    } catch (reason) {
      if (generation === requestGeneration.current) setError(reason instanceof Error ? reason.message : 'Inspection impossible')
    } finally {
      if (generation === requestGeneration.current) setPreviewing(false)
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file || !preview) return
    const generation = requestGeneration.current
    setLoading(true)
    setError(null)
    setReport(null)
    setStep('audit')
    startProgress()

    const form = new FormData()
    form.append('configuration', file)
    const uniqueNames = [...new Set(selectedWanScopes.map((scope) => scope.name))]
    if (uniqueNames.length === selectedWanScopes.length) uniqueNames.forEach((name) => form.append('selected_wans', name))
    form.append('selected_wan_scopes', JSON.stringify(selectedWanScopes))
    if (client) form.append('client', client)
    if (site) form.append('site', site)
    if (serialNumber) form.append('serial_number', serialNumber)
    if (licenseEndDate) form.append('utm_license_expiration', licenseEndDate)
    if (uptime) form.append('uptime', uptime)
    form.append('schedule_reference_instant', new Date().toISOString())
    if (unmatchedRules) form.append('unmatched_rules', unmatchedRules)
    if (ha) form.append('ha_cabling_redundancy', ha)
    if (mpls) form.append('mpls_context', mpls)
    if (utmLicense) {
      form.append('utm_license', utmLicense)
      form.append('utm_license_status', utmLicense === 'true' ? 'active' : 'inactive')
      form.append('utm_license_manual', 'true')
    }
    form.append('context_source', 'operator-form')
    form.append('context_method', 'manual-selection')

    try {
      const response = await fetch('/api/audits', { method: 'POST', body: form })
      if (!response.ok) throw await responseError(response, 'Audit')
      const audited = (await response.json()) as AuditReport
      if (generation === requestGeneration.current) {
        stopProgress()
        setProgress(100)
        setReport(audited)
        setStep('results')
      }
    } catch (reason) {
      if (generation === requestGeneration.current) {
        stopProgress()
        setProgress(0)
        setError(reason instanceof Error ? reason.message : 'Audit impossible')
        setStep('options')
      }
    } finally {
      if (generation === requestGeneration.current) setLoading(false)
    }
  }

  function resetAudit() {
    requestGeneration.current += 1
    stopProgress()
    setProgress(0)
    setStep('upload')
    setFile(null)
    setPreview(null)
    setReport(null)
    setSelectedWanScopes([])
    setError(null)
    setLoading(false)
    setPreviewing(false)
    setClient('')
    setSite('')
    setSerialNumber('')
    setLicenseEndDate('')
    setUptime('')
    setUnmatchedRules('0')
    setHa('false')
    setMpls('false')
    setUtmLicense('false')
    if (fileInput.current) fileInput.current.value = ''
  }

  function hasScope(name: string, kind: WanSelectionKind): boolean {
    return selectedWanScopes.some((scope) => scope.name === name && scope.kind === kind)
  }

  function toggleWan(name: string, kind: WanSelectionKind) {
    setSelectedWanScopes((current) => {
      const selected = current.some((scope) => scope.name === name && scope.kind === kind)
      return selected
        ? current.filter((scope) => !(scope.name === name && scope.kind === kind))
        : [...current, { name, kind }]
    })
  }

  const findings = report?.findings ?? []
  const presentation = report?.presentation
  const clientRows: PresentationRow[] = presentation
    ? [...presentation.business_rows, ...presentation.v2_only_rows, ...(presentation.engine_error_rows ?? [])]
    : findings.map((finding): PresentationRow => ({
      business_key: finding.control_id,
      order: 0,
      display_name: finding.display_name ?? finding.title,
      relation: 'engine',
      classification: 'V2',
      presentation_kind: 'engine',
      v2_control_ids: [finding.control_id],
      status: finding.status,
      result: null,
      finding_ids: [finding.control_id],
    }))
  const nonConform = clientRows.filter((row) => row.status === 'FAIL' || row.status === 'UNKNOWN' || row.status === 'ERROR')
  const sdwanMembers = preview?.sdwan_members ?? []
  const sdwanMemberNames = new Set(sdwanMembers.map((member) => member.name.toLocaleLowerCase()))

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
            <p><strong>Hostname:</strong> <span>{display(preview.hostname)}</span> | <strong>Version:</strong> <span>{display(preview.firmware_version)}</span> | <strong>Model:</strong> <span>{display(preview.model)}</span></p>
          </div>

          <div className="options-form">
            <label className="checkbox-item"><span>Nom du client</span><input aria-label="Client" type="text" value={client} onChange={(event) => setClient(event.target.value)} className="text-input" /></label>
            <label className="checkbox-item"><span>Nom du site</span><input aria-label="Site" type="text" value={site} onChange={(event) => setSite(event.target.value)} className="text-input" /></label>
            <label className="checkbox-item"><span>Numéro de série</span><input type="text" value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)} className="text-input" /></label>
            <label className="checkbox-item"><span>Date de fin de licence</span><input type="date" value={licenseEndDate} onChange={(event) => setLicenseEndDate(event.target.value)} className="date-input" /></label>
            <label className="checkbox-item"><span>System Uptime</span><input aria-label="Uptime" type="text" placeholder="42 days, 03:12:10" value={uptime} onChange={(event) => setUptime(event.target.value)} className="text-input" /></label>
          </div>

          <div className="button-group">
            <button onClick={() => setStep('upload')} className="button secondary" type="button" aria-label="Retour à l’upload">Back</button>
            <button onClick={() => setStep('wan')} className="button primary" type="button" aria-label="Continuer vers la sélection WAN">Continue</button>
          </div>
        </section>
      </form>}

      {preview && step === 'wan' && <section className="step wan-step" aria-label="Sélection WAN">
        <h2 aria-label="Sélection WAN">Etape 3 : Sélection des WAN Interfaces</h2>

        <fieldset className="selection-section" aria-label="Interfaces WAN">
          <h3>Interfaces WAN à sélectionner</h3>
          <div className="checkbox-list interfaces-list">
            {preview.interfaces.filter((item) => item.name.trim() && !sdwanMemberNames.has(item.name.toLocaleLowerCase())).map((item) => <label key={`interface-${item.name}`} className="checkbox-item">
              <input aria-label={`WAN ${item.name}`} type="checkbox" checked={hasScope(item.name, 'interface')} onChange={() => toggleWan(item.name, 'interface')} />
              <span>{item.name}</span>
            </label>)}
            {preview.interfaces.filter((item) => item.name.trim() && !sdwanMemberNames.has(item.name.toLocaleLowerCase())).length === 0 && <p className="empty-state">Aucune interface hors SD-WAN détectée.</p>}
          </div>
        </fieldset>

        {sdwanMembers.length > 0 && <fieldset className="selection-section" aria-label="Membres physiques SD-WAN">
          <h3>Membres physiques SD-WAN à sélectionner</h3>
          <div className="checkbox-list sdwan-members-list">
            {sdwanMembers.map((member) => <label key={`sdwan-member-${member.name}`} className="checkbox-item">
              <input aria-label={`WAN membre SD-WAN ${member.name}`} type="checkbox" checked={hasScope(member.name, 'interface')} onChange={() => toggleWan(member.name, 'interface')} />
              <span>{member.name} <small>(zone{member.zones.length > 1 ? 's' : ''} : {member.zones.join(', ')})</small></span>
            </label>)}
          </div>
        </fieldset>}

        <fieldset className="selection-section" aria-label="Zones">
          <h3>Zones WAN à sélectionner</h3>
          <div className="checkbox-list zones-list">
            {preview.zones.filter((zone) => zone.name.trim()).map((zone) => <label key={`zone-${zone.name}`} className="checkbox-item">
              <input aria-label={`WAN zone ${zone.name}`} type="checkbox" checked={hasScope(zone.name, 'zone')} onChange={() => toggleWan(zone.name, 'zone')} />
              <span>Zone: {zone.name} ({zone.interfaces.join(', ')})</span>
            </label>)}
            {preview.zones.length === 0 && <p className="empty-state">Aucune zone WAN détectée.</p>}
          </div>
        </fieldset>

        <fieldset className="selection-section" aria-label="SD-WAN">
          <h3>SD-WAN Zones</h3>
          <div className="checkbox-list sdwan-list">
            {preview.sdwan_zones.filter((zone) => zone.name.trim()).map((zone) => <label key={`sdwan-${zone.name}`} className="checkbox-item">
              <input aria-label={`WAN sdwan ${zone.name}`} type="checkbox" checked={hasScope(zone.name, 'sdwan')} onChange={() => toggleWan(zone.name, 'sdwan')} />
              <span>SD-WAN Zone: {zone.name} → {zone.interfaces.length > 0 ? zone.interfaces.join(', ') : 'Aucun membre observé'}{zone.proof_state === 'unknown' ? ' (à vérifier)' : ''}</span>
            </label>)}
            {preview.sdwan_zones.length === 0 && <p className="empty-state">Aucune zone SD-WAN détectée.</p>}
          </div>
        </fieldset>

        <div className="button-group">
          <button className="button secondary" type="button" onClick={() => setStep('context')} aria-label="Retour au contexte">Back</button>
          <button className="button primary" type="button" onClick={() => setStep('options')} aria-label="Continuer vers les options d’audit">Continue</button>
        </div>
      </section>}

      {preview && step === 'options' && <form onSubmit={submit}>
        <section className="step" aria-label="Options d’audit">
          <h2 aria-label="Options d’audit">Etape 4 : Options d'audit</h2>
          <div className="options-form">
            <label className="checkbox-item"><input aria-label="Licence UTM active" type="checkbox" checked={utmLicense === 'true'} onChange={(event) => setUtmLicense(event.target.checked ? 'true' : 'false')} /><span>Licence UTM Valide</span></label>
            <label className="checkbox-item"><input aria-label="MPLS / L2L présent" type="checkbox" checked={mpls === 'true'} onChange={(event) => setMpls(event.target.checked ? 'true' : 'false')} /><span>Lien MPLS ou L2L</span></label>
            <label className="checkbox-item"><input aria-label="HA présent" type="checkbox" checked={ha === 'true'} onChange={(event) => setHa(event.target.checked ? 'true' : 'false')} /><span>Redondance câblage HA</span></label>
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

      {report && preview && step === 'results' && <section className="step results" aria-live="polite">
        <h2 aria-label="Synthèse et résultats">Audit Complete</h2>
        <div className="info-box" aria-label="Synthèse de l’audit">
          <p><strong>Hostname:</strong> <span>{display(preview.hostname)}</span> | <strong>Version:</strong> <span>{display(preview.firmware_version)}</span> | <strong>Model:</strong> <span>{display(preview.model)}</span></p>
          <p><strong>Total Checks:</strong> {findings.length}</p>
          {presentation && <>
            <p><strong>Points métier V1 comparables:</strong> {presentation.business_control_count} | <strong>Contrôles moteur V2:</strong> {presentation.engine_control_count}</p>
            <p className="field-hint">{presentation.split_extra_finding_count} sous-vérifications détaillent des points V1 ; {presentation.v2_only_control_count} contrôles complémentaires sont séparés de la lecture métier.</p>
          </>}
        </div>

        {nonConform.length > 0 ? <div className="reports-section">
          <h3>Contrôles non conformes ou à vérifier</h3>
          <div className="checks-table-wrapper"><table className="checks-table"><thead><tr><th>Contrôle</th><th className="checks-status-col">Statut</th></tr></thead><tbody>
            {nonConform.map((finding) => {
              const status = finding.status ?? 'UNKNOWN'
              const statusLabel = status === 'FAIL' ? 'NON CONFORME' : status === 'ERROR' ? 'ERREUR' : 'À VÉRIFIER'
              return <tr key={finding.business_key}><td className="checks-name">{finding.display_name}</td><td className="checks-status"><span className={`status-icon ${status.toLowerCase()}`} aria-label={statusLabel} title={statusLabel}>{status === 'FAIL' ? '✕' : status === 'ERROR' ? '!' : '?'}</span></td></tr>
            })}
          </tbody></table></div>
        </div> : <div className="reports-section"><h3>Contrôles</h3><div className="info-box">✅ Aucun contrôle non conforme détecté.</div></div>}

        <div className="reports-section"><h3>Download Reports</h3><div className="button-group report-downloads">
          <a href={`/api/reports/${report.report_id}.json`} className="button primary">Download JSON Report</a>
          <a href={`/api/reports/${report.report_id}.xlsx`} className="button primary">Download Excel Report</a>
          <a href={`/api/reports/${report.report_id}.docx`} className="button primary">Download Word Report</a>
        </div></div>
        <div className="button-group"><button onClick={resetAudit} className="button secondary" type="button" aria-label="Nouvel audit">Start New Audit</button></div>
      </section>}
    </main>
    <footer className="footer"><p>Vysion</p></footer>
  </div>
}

export default App
