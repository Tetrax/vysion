import { FormEvent, Fragment, KeyboardEvent, ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import './app.css'

type AdminStatus = {
  setup_required: boolean
  authenticated: boolean
  csrf_token: string | null
  session_expires_at: string | null
  tls_backend: string
  tls_hostname: string | null
  recovery_enabled: boolean
  version: string
}

type SessionRow = { created_at: string; expires_at: string; current: boolean }

type CertificateInfo = {
  subject: string
  issuer: string
  not_after: string
  sha256: string
  sans: string[]
  chain_length: number
  hostname: string
}

type CertificatesStatus = {
  managed: boolean
  tls_backend: string
  tls_hostname: string | null
  active: (CertificateInfo & { number: number }) | null
  staging: CertificateInfo | null
  generations: (CertificateInfo & { number: number; is_active: boolean })[]
}

type Validation = { certificate: CertificateInfo; ticket: { token: string; expires_in: number } }

type EmailStatus = {
  configured: boolean
  transport: string | null
  provenance: string | null
  secret_configured: boolean
  recovery_email_configured: boolean
  recovery_enabled: boolean
}

type EmailTransport = 'smtp' | 'microsoft365'

type ThemeChoice = 'system' | 'light' | 'dark'
type TabId = 'certificates' | 'email' | 'system' | 'account'

const THEME_STORAGE_KEY = 'vysion-theme'
const THEME_ORDER: ThemeChoice[] = ['system', 'light', 'dark']
const THEME_LABELS: Record<ThemeChoice, string> = {
  system: 'Thème : système',
  light: 'Thème : clair',
  dark: 'Thème : sombre',
}
const PASSWORD_HELP = '12 à 1 024 octets UTF-8.'
// Quatre onglets métier : la Vue d'ensemble n'en est pas un, c'est le bandeau
// de statuts commun posé au-dessus du panneau actif.
const TABS: { id: TabId; label: string; eyebrow: string }[] = [
  { id: 'certificates', label: 'Certificats', eyebrow: 'TLS' },
  { id: 'email', label: 'Messagerie', eyebrow: 'Messages' },
  { id: 'system', label: 'Système', eyebrow: 'Exploitation' },
  { id: 'account', label: 'Compte', eyebrow: 'Sécurité' },
]

async function readDetail(response: Response, action: string): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: unknown }
    if (typeof payload.detail === 'string') return `${action} : ${payload.detail}`
  } catch {
    // Non-JSON body: fall back to the status line.
  }
  return `${action} (HTTP ${response.status})`
}

function shortFingerprint(value: string): string {
  return value.slice(0, 16)
}

function sessionsLabel(count: number): string {
  return count === 1 ? '1 session ouverte' : `${count} sessions ouvertes`
}

function transportLabel(transport: string | null): string {
  return transport === 'microsoft365' ? 'Microsoft 365' : 'SMTP'
}

function readStoredTheme(): ThemeChoice {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // Stockage local indisponible : on suit la préférence système.
  }
  return 'system'
}

function applyTheme(choice: ThemeChoice): void {
  const root = document.documentElement
  if (choice === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', choice)
}

function persistTheme(choice: ThemeChoice): void {
  try {
    if (choice === 'system') window.localStorage.removeItem(THEME_STORAGE_KEY)
    else window.localStorage.setItem(THEME_STORAGE_KEY, choice)
  } catch {
    // Stockage local indisponible : le choix reste valable pour cette session.
  }
}

function AdminApp() {
  const [status, setStatus] = useState<AdminStatus | null>(null)
  const [csrf, setCsrf] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [sessions, setSessions] = useState<SessionRow[]>([])
  const [certificates, setCertificates] = useState<CertificatesStatus | null>(null)
  const [email, setEmail] = useState<EmailStatus | null>(null)
  const [emailTransport, setEmailTransport] = useState<EmailTransport>('smtp')
  const transportSeeded = useRef(false)
  const [validation, setValidation] = useState<Validation | null>(null)
  const [theme, setTheme] = useState<ThemeChoice>(() => readStoredTheme())
  const [activeTab, setActiveTab] = useState<TabId>('certificates')
  const tabRefs = useRef<Partial<Record<TabId, HTMLButtonElement | null>>>({})

  const refresh = useCallback(async () => {
    try {
      const response = await fetch('/api/admin/status')
      if (!response.ok) {
        setError(await readDetail(response, 'Statut indisponible'))
        return
      }
      const next = (await response.json()) as AdminStatus
      setStatus(next)
      setValidation(null)
      if (next.authenticated && next.csrf_token) {
        setCsrf(next.csrf_token)
        setError(null)
        const [listResponse, certificatesResponse, emailResponse] = await Promise.all([
          fetch('/api/admin/sessions'),
          fetch('/api/admin/certificates'),
          fetch('/api/admin/email'),
        ])
        if (listResponse.ok) {
          const payload = (await listResponse.json()) as { sessions: SessionRow[] }
          setSessions(payload.sessions)
        }
        if (certificatesResponse.ok) {
          setCertificates((await certificatesResponse.json()) as CertificatesStatus)
        }
        if (emailResponse.ok) {
          const payload = (await emailResponse.json()) as EmailStatus
          setEmail(payload)
          if (!transportSeeded.current && payload.transport) {
            transportSeeded.current = true
            setEmailTransport(payload.transport === 'microsoft365' ? 'microsoft365' : 'smtp')
          }
        }
      } else {
        setCsrf('')
        setSessions([])
        setCertificates(null)
        setEmail(null)
        transportSeeded.current = false
        setEmailTransport('smtp')
      }
    } catch {
      setError('API administrateur injoignable')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    applyTheme(theme)
    persistTheme(theme)
  }, [theme])

  const authenticated = Boolean(status?.authenticated)

  async function mutate(path: string, init: RequestInit): Promise<Response> {
    return fetch(path, {
      ...init,
      headers: {
        ...(init.headers as Record<string, string> | undefined),
        'X-CSRF-Token': csrf,
        Origin: window.location.origin,
      },
    })
  }

  async function submitCredentials(event: FormEvent<HTMLFormElement>, path: string) {
    event.preventDefault()
    const form = event.currentTarget
    const password = new FormData(form).get('password')
    try {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: window.location.origin },
        body: JSON.stringify({ password }),
      })
      if (!response.ok) {
        setError(await readDetail(response, path === '/api/admin/setup' ? 'Configuration' : 'Connexion'))
        return
      }
      form.reset()
      await refresh()
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitLogout() {
    try {
      await mutate('/api/admin/logout', { method: 'POST' })
      await refresh()
    } catch {
      setError('Déconnexion impossible')
    }
  }

  async function submitPasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const response = await mutate('/api/admin/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          current_password: data.get('current_password'),
          password: data.get('password'),
        }),
      })
      if (!response.ok) {
        setError(await readDetail(response, 'Changement de mot de passe'))
        return
      }
      form.reset()
      setMessage('Mot de passe modifié')
      await refresh()
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitRevoke() {
    try {
      const response = await mutate('/api/admin/sessions/revoke', { method: 'POST' })
      if (!response.ok) {
        setError(await readDetail(response, 'Révocation des sessions'))
        return
      }
      setMessage('Toutes les sessions ont été révoquées')
      await refresh()
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitRecoveryRequest() {
    try {
      const response = await fetch('/api/admin/recovery/request', {
        method: 'POST',
        headers: { Origin: window.location.origin },
      })
      if (!response.ok) {
        setError(await readDetail(response, 'Récupération'))
        return
      }
      setMessage('Si un compte existe, un courriel de récupération a été envoyé')
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitRecoveryConfirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const response = await fetch('/api/admin/recovery/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: window.location.origin },
        body: JSON.stringify({ token: data.get('token'), password: data.get('password') }),
      })
      if (!response.ok) {
        setError(await readDetail(response, 'Confirmation de récupération'))
        return
      }
      form.reset()
      setMessage('Mot de passe réinitialisé, connectez-vous')
      await refresh()
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitValidation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const response = await mutate('/api/admin/certificates/validate', {
        method: 'POST',
        body: data,
      })
      if (!response.ok) {
        setError(await readDetail(response, 'Validation du certificat'))
        setValidation(null)
        return
      }
      setValidation((await response.json()) as Validation)
      setError(null)
      setMessage('Certificat validé : vérifiez les métadonnées puis activez-le')
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitActivation() {
    if (!validation) return
    try {
      const response = await mutate('/api/admin/certificates/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: validation.ticket.token }),
      })
      if (!response.ok) {
        setError(await readDetail(response, "Activation du certificat"))
        return
      }
      const payload = (await response.json()) as { generation: number }
      setValidation(null)
      setError(null)
      setMessage(`Certificat activé (génération ${payload.generation})`)
      await refresh()
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const value = (name: string) => String(data.get(name) ?? '').trim()
    const rawPort = value('smtp_port')
    const body = {
      transport: emailTransport,
      from_address: value('from_address'),
      recovery_email: value('recovery_email'),
      timeout_seconds: Number(value('timeout_seconds') || '10'),
      smtp_host: value('smtp_host'),
      smtp_port: rawPort === '' ? null : Number(rawPort),
      smtp_security: value('smtp_security') || null,
      smtp_username: value('smtp_username'),
      smtp_password: String(data.get('smtp_password') ?? ''),
      smtp_allow_plaintext: data.get('smtp_allow_plaintext') === 'on',
      m365_tenant_id: value('m365_tenant_id'),
      m365_client_id: value('m365_client_id'),
      m365_client_secret: String(data.get('m365_client_secret') ?? ''),
      m365_mailbox: value('m365_mailbox'),
    }
    setError(null)
    setMessage(null)
    try {
      const response = await mutate('/api/admin/email', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        setError(await readDetail(response, 'Enregistrement impossible'))
        return
      }
      setEmail((await response.json()) as EmailStatus)
      setMessage('Configuration email enregistrée')
      // The secret was consumed by this save: never leave it sitting in the
      // form. An empty field then means "keep what was just stored".
      for (const name of ['smtp_password', 'm365_client_secret']) {
        const field = form.elements.namedItem(name)
        if (field instanceof HTMLInputElement) field.value = ''
      }
    } catch {
      setError('API administrateur injoignable')
    }
  }

  async function submitEmailTest() {
    setError(null)
    setMessage(null)
    try {
      const response = await mutate('/api/admin/email/test', { method: 'POST' })
      if (!response.ok) {
        setError(await readDetail(response, 'Test impossible'))
        return
      }
      const payload = (await response.json()) as { transport: string }
      setMessage(`Email de test envoyé via ${payload.transport}`)
    } catch {
      setError('API administrateur injoignable')
    }
  }

  function cycleTheme() {
    setTheme((current) => {
      const index = THEME_ORDER.indexOf(current)
      return THEME_ORDER[(index + 1) % THEME_ORDER.length]
    })
  }

  function onTabListKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const index = TABS.findIndex((tab) => tab.id === activeTab)
    let nextIndex: number
    switch (event.key) {
      case 'ArrowRight':
        nextIndex = (index + 1) % TABS.length
        break
      case 'ArrowLeft':
        nextIndex = (index - 1 + TABS.length) % TABS.length
        break
      case 'Home':
        nextIndex = 0
        break
      case 'End':
        nextIndex = TABS.length - 1
        break
      default:
        return
    }
    event.preventDefault()
    const next = TABS[nextIndex].id
    setActiveTab(next)
    tabRefs.current[next]?.focus()
  }

  // One abstraction in the UI too: `local` and `helper` both terminate TLS
  // under Vysion's control, `none` leaves it to the host proxy.
  const helperMode = status?.tls_backend === 'helper'
  const managed = status?.tls_backend === 'local' || helperMode
  const tlsBadge = helperMode ? 'Helper' : status?.tls_backend === 'local' ? 'Standalone' : 'Proxy'
  const deploymentMode = helperMode
    ? 'Helper — Vysion pilote le Nginx hôte via un service root'
    : status?.tls_backend === 'local'
      ? 'Standalone — Vysion gère le certificat TLS'
      : 'Proxy — TLS géré par le proxy hôte'

  const topbar = (
    <header className="admin-topbar">
      <div className="admin-brand">
        <span className="admin-mark" aria-hidden="true">V</span>
        <div className="admin-brand-text">
          <h1 className="admin-brand-name">Vysion</h1>
          <span className="admin-subtitle">Administration</span>
        </div>
      </div>
      <div className="admin-toolbar">
        <button type="button" className="button secondary admin-theme-toggle" onClick={cycleTheme}>
          {THEME_LABELS[theme]}
        </button>
        <a className="button secondary" href="/">Retour à l’audit</a>
        {authenticated && (
          <button type="button" className="button danger" onClick={() => void submitLogout()}>
            Se déconnecter
          </button>
        )}
      </div>
    </header>
  )

  const messages = (
    <div className="admin-messages">
      {error && (
        <p role="alert" className="admin-message admin-message--error">
          <span className="admin-message-mark" aria-hidden="true">!</span>
          <span>{error}</span>
        </p>
      )}
      {message && (
        <p role="status" className="admin-message admin-message--success">
          <span className="admin-message-mark" aria-hidden="true">✓</span>
          <span>{message}</span>
        </p>
      )}
    </div>
  )

  const footer = (
    <footer className="admin-footer">
      <p>Vysion — administration privée</p>
    </footer>
  )

  let body = <p className="admin-loading" role="status">Chargement de l’administration…</p>

  if (status && !status.authenticated) {
    body = (
      <>
        <section className="admin-notice" aria-label="Information de sécurité">
          <span className="admin-notice-icon" aria-hidden="true">◆</span>
          <div>
            <strong>Zone d’administration privée</strong>
            <p>
              Cette page configure l’accès à l’administration de Vysion : mot de passe,
              récupération de l’accès, puis sessions et certificats TLS une fois connecté.
            </p>
          </div>
        </section>

        <div className="admin-auth-layout">
          <div className="admin-panel">
            <div className="admin-panel-header">
              <p className="admin-eyebrow">{status.setup_required ? 'Première configuration' : 'Accès restreint'}</p>
              <h2 className="admin-panel-title">
                {status.setup_required ? 'Configuration initiale' : 'Connexion'}
              </h2>
              <p className="admin-panel-copy">
                {status.setup_required
                  ? 'Créez le mot de passe administrateur qui protégera Vysion.'
                  : 'Connectez-vous pour gérer les sessions et les certificats TLS de Vysion.'}
              </p>
            </div>
            <div className="admin-panel-body">
              {status.setup_required ? (
                <form onSubmit={(event) => void submitCredentials(event, '/api/admin/setup')}>
                  <div className="admin-field">
                    <label htmlFor="setup-password">Nouveau mot de passe administrateur</label>
                    <input
                      id="setup-password"
                      name="password"
                      type="password"
                      required
                      autoComplete="new-password"
                      aria-describedby="setup-password-help"
                    />
                    <span className="admin-help" id="setup-password-help">{PASSWORD_HELP}</span>
                  </div>
                  <button type="submit" className="button primary admin-submit">
                    Créer le compte administrateur
                  </button>
                </form>
              ) : (
                <form onSubmit={(event) => void submitCredentials(event, '/api/admin/login')}>
                  <div className="admin-field">
                    <label htmlFor="login-password">Mot de passe</label>
                    <input id="login-password" name="password" type="password" required autoComplete="current-password" />
                  </div>
                  <button type="submit" className="button primary admin-submit">Se connecter</button>
                </form>
              )}
            </div>
          </div>

          {!status.setup_required && status.recovery_enabled && (
            <div className="admin-panel">
              <div className="admin-panel-header">
                <p className="admin-eyebrow">Accès</p>
                <h2 className="admin-panel-title">Récupération de l’accès</h2>
                <p className="admin-panel-copy">
                  Recevez un lien à usage unique pour choisir un nouveau mot de passe.
                </p>
              </div>
              <div className="admin-panel-body">
                <button type="button" className="button secondary" onClick={() => void submitRecoveryRequest()}>
                  Recevoir un lien de récupération
                </button>
                <form onSubmit={(event) => void submitRecoveryConfirm(event)}>
                  <div className="admin-field">
                    <label htmlFor="recovery-token">Jeton de récupération</label>
                    <input id="recovery-token" name="token" type="text" required />
                  </div>
                  <div className="admin-field">
                    <label htmlFor="recovery-password">Nouveau mot de passe</label>
                    <input
                      id="recovery-password"
                      name="password"
                      type="password"
                      required
                      autoComplete="new-password"
                      aria-describedby="recovery-password-help"
                    />
                    <span className="admin-help" id="recovery-password-help">{PASSWORD_HELP}</span>
                  </div>
                  <button type="submit" className="button primary admin-submit">Utiliser le jeton</button>
                </form>
              </div>
            </div>
          )}
        </div>
      </>
    )
  }

  if (status && status.authenticated) {
    const certificateSummary = !managed
      ? 'Géré par le proxy hôte'
      : certificates?.active
        ? `Génération ${certificates.active.number}`
        : 'Non activé'
    const certificateDetail = !managed
      ? 'Aucune gestion de certificat dans Vysion'
      : certificates?.active
        ? `Expire le ${certificates.active.not_after}`
        : 'Aucune génération active.'

    // Bandeau de statuts commun : posé au-dessus du panneau actif, jamais
    // présenté comme un onglet de plus.
    const statusStrip = (
      <section className="admin-status-strip" aria-label="État courant">
        <div className="admin-status-item">
          <span className="admin-status-label">Version</span>
          <strong className="admin-status-value">{status.version}</strong>
        </div>
        <div className="admin-status-item">
          <span className="admin-status-label">TLS</span>
          <strong className="admin-status-value">{tlsBadge}</strong>
          <span className="admin-status-detail">{status.tls_hostname ?? 'Nom TLS non configuré'}</span>
        </div>
        <div className="admin-status-item">
          <span className="admin-status-label">Session</span>
          <strong className="admin-status-value">Expire le {status.session_expires_at ?? 'inconnue'}</strong>
          <span className="admin-status-detail">{sessionsLabel(sessions.length)}</span>
        </div>
        <div className="admin-status-item">
          <span className="admin-status-label">Certificat</span>
          <strong className="admin-status-value">{certificateSummary}</strong>
          <span className="admin-status-detail">{certificateDetail}</span>
        </div>
      </section>
    )

    const tablist = (
      <div
        className="admin-tablist"
        role="tablist"
        aria-label="Sections d’administration"
        onKeyDown={onTabListKeyDown}
      >
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            id={`admin-tab-${tab.id}`}
            aria-selected={activeTab === tab.id}
            aria-controls={`admin-panel-${tab.id}`}
            tabIndex={activeTab === tab.id ? 0 : -1}
            className={`admin-tab${activeTab === tab.id ? ' admin-tab--active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
            ref={(node) => {
              tabRefs.current[tab.id] = node
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>
    )

    let certificatesPanel: ReactNode = null
    if (managed) {
      const stepStates = [
        validation ? 'Validé' : 'En cours',
        validation ? 'Contrôles réussis' : 'En attente',
        validation ? 'Prêt' : 'En attente',
      ]
      const stepTitles = ['Valider les fichiers', 'Contrôles cryptographiques', 'Activer la génération']
      certificatesPanel = (
        <>
          <ol className="admin-steps" aria-label="Parcours du certificat">
            {stepTitles.map((title, index) => (
              <li
                key={title}
                className={`admin-step${validation && index > 0 ? ' admin-step--done' : ''}`}
              >
                <span className="admin-step-index" aria-hidden="true">{index + 1}</span>
                <span className="admin-step-title">{title}</span>
                <span className="admin-step-state">{stepStates[index]}</span>
              </li>
            ))}
          </ol>

          {!certificates ? (
            <p className="admin-loading" role="status">Chargement des certificats…</p>
          ) : (
            <div className="admin-grid admin-grid--2">
              <div className="admin-panel">
                <div className="admin-panel-header">
                  <p className="admin-eyebrow">État</p>
                  <h3 className="admin-panel-title">Certificats installés</h3>
                  <p className="admin-panel-copy">
                    Lecture seule : la validation et l’activation passent par le formulaire d’import.
                  </p>
                </div>
                <div className="admin-panel-body">
                  <h4 className="admin-subheading">Actif</h4>
                  {certificates.active ? (
                    <dl className="admin-deflist">
                      <div>
                        <dt>Génération</dt>
                        <dd>#{certificates.active.number}</dd>
                      </div>
                      <div>
                        <dt>Sujet</dt>
                        <dd>{certificates.active.subject}</dd>
                      </div>
                      <div>
                        <dt>Expire le</dt>
                        <dd>{certificates.active.not_after}</dd>
                      </div>
                      <div>
                        <dt>Empreinte SHA-256</dt>
                        <dd className="admin-mono">{shortFingerprint(certificates.active.sha256)}…</dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="admin-empty">Aucun certificat actif.</p>
                  )}

                  <h4 className="admin-subheading">Candidat en attente</h4>
                  {certificates.staging ? (
                    <dl className="admin-deflist">
                      <div>
                        <dt>Sujet</dt>
                        <dd>{certificates.staging.subject}</dd>
                      </div>
                      <div>
                        <dt>Expire le</dt>
                        <dd>{certificates.staging.not_after}</dd>
                      </div>
                      <div>
                        <dt>Empreinte SHA-256</dt>
                        <dd className="admin-mono">{shortFingerprint(certificates.staging.sha256)}…</dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="admin-empty">Aucun candidat en attente.</p>
                  )}

                  <h4 className="admin-subheading">Générations</h4>
                  <ul className="admin-list">
                    {certificates.generations.map((generation) => (
                      <li key={generation.number}>
                        <span>#{generation.number}{generation.is_active ? ' — actif' : ''}</span>
                        <span>Expire le {generation.not_after}</span>
                      </li>
                    ))}
                    {certificates.generations.length === 0 && (
                      <li className="admin-empty">Aucune génération.</li>
                    )}
                  </ul>
                </div>
              </div>

              <div className="admin-panel">
                <div className="admin-panel-header">
                  <p className="admin-eyebrow">Import</p>
                  <h3 className="admin-panel-title">Valider un certificat</h3>
                  <p className="admin-panel-copy">
                    PEM complet ou archive PKCS#12. La validation ne modifie rien tant que la
                    génération n’est pas activée.
                  </p>
                </div>
                <div className="admin-panel-body">
                  <form onSubmit={(event) => void submitValidation(event)}>
                    <div className="admin-field">
                      <label htmlFor="certificate-file">Certificat (PEM complet ou archive PKCS#12)</label>
                      <input id="certificate-file" name="certificate" type="file" />
                    </div>
                    <div className="admin-field">
                      <label htmlFor="key-file">Clé privée (PEM, facultatif pour une archive)</label>
                      <input id="key-file" name="private_key" type="file" />
                    </div>
                    <div className="admin-field">
                      <label htmlFor="passphrase-input">Passphrase de l’archive (facultative)</label>
                      <input id="passphrase-input" name="passphrase" type="password" autoComplete="off" />
                    </div>
                    <button type="submit" className="button primary admin-submit">Valider le certificat</button>
                  </form>

                  {validation && (
                    <div className="admin-activation">
                      <div>
                        <strong>Validation réussie</strong>
                        <p>
                          {validation.certificate.subject} — expire le {validation.certificate.not_after} —
                          chaîne de {validation.certificate.chain_length} certificat(s) — hostname{' '}
                          {validation.certificate.hostname}
                        </p>
                      </div>
                      <button type="button" className="button primary" onClick={() => void submitActivation()}>
                        Activer le certificat
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )
    } else {
      certificatesPanel = (
        <div className="admin-note">
          <strong>Le TLS est géré par le proxy hôte</strong>
          <p>
            Ce déploiement tourne en mode proxy : le certificat est demandé, renouvelé et servi
            par le proxy hôte, et Vysion reçoit le trafic déjà terminé.
          </p>
          <p>
            Vysion n’importe ni n’active aucun certificat dans ce mode. Pour renouveler le
            certificat, agissez côté proxy hôte : la configuration de Vysion reste inchangée.
          </p>
        </div>
      )
    }

    const emailPanel = !email ? (
      <p className="admin-loading" role="status">Chargement de la configuration email…</p>
    ) : (
      <div className="admin-grid admin-grid--2">
        <div className="admin-panel">
          <div className="admin-panel-header">
            <p className="admin-eyebrow">État</p>
            <h3 className="admin-panel-title">Configuration du transport</h3>
            <p className="admin-panel-copy">
              Seuls l’état et la provenance sont affichés : aucun secret ne quitte le serveur.
            </p>
          </div>
          <div className="admin-panel-body">
            <p className={`admin-state-line ${email.configured ? 'admin-state-line--ok' : 'admin-state-line--warn'}`}>
              <span className="admin-state-dot" aria-hidden="true" />
              <strong>
                {email.configured
                  ? `Configuration complète — ${transportLabel(email.transport)}`
                  : 'Configuration incomplète'}
              </strong>
            </p>
            <dl className="admin-deflist">
              <div>
                <dt>Transport</dt>
                <dd>{transportLabel(email.transport)}</dd>
              </div>
              <div>
                <dt>Adresse de récupération</dt>
                <dd>{email.recovery_email_configured ? 'Enregistrée' : 'Absente'}</dd>
              </div>
              <div>
                <dt>Récupération du compte</dt>
                <dd>
                  {email.recovery_enabled
                    ? 'Disponible avec ce transport'
                    : 'Indisponible — configuration ou origine publique incomplètes'}
                </dd>
              </div>
            </dl>
          </div>
        </div>

        <div className="admin-panel">
          <div className="admin-panel-header">
            <p className="admin-eyebrow">Configuration</p>
            <h3 className="admin-panel-title">Configurer le transport</h3>
            <p className="admin-panel-copy">
              Champs secrets en écriture seule : les laisser vide conserve la valeur enregistrée.
            </p>
          </div>
          <div className="admin-panel-body">
            <form onSubmit={(event) => void submitEmail(event)}>
              <div className="admin-field admin-field--choice">
                <label htmlFor="email-transport">Comment voulez-vous envoyer les courriels ?</label>
                <select
                  id="email-transport"
                  name="transport"
                  value={emailTransport}
                  onChange={(event) =>
                    setEmailTransport(event.target.value === 'microsoft365' ? 'microsoft365' : 'smtp')
                  }
                >
                  <option value="smtp">SMTP</option>
                  <option value="microsoft365">Microsoft 365 (OAuth2, client credentials)</option>
                </select>
                <span className="admin-help">
                  Le transport sélectionné détermine les groupes de champs ci-dessous.
                </span>
              </div>

              <fieldset className="admin-fieldset">
                <legend className="admin-fieldset-legend">Communs</legend>
                <div className="admin-field">
                  <label htmlFor="email-from">Adresse d’expédition</label>
                  <input id="email-from" name="from_address" type="email" required autoComplete="email" />
                  <span className="admin-help">
                    Expéditeur des messages envoyés par Vysion (récupération et tests).
                  </span>
                </div>
              </fieldset>

              <fieldset className="admin-fieldset">
                <legend className="admin-fieldset-legend">Connexion et identité</legend>
                {emailTransport === 'smtp' ? (
                  // Keyed: switching transport must remount the fields,
                  // never reuse the other transport's inputs (React would
                  // otherwise carry the port default into the client ID).
                  <Fragment key="smtp-connection">
                    <div className="admin-field">
                      <label htmlFor="smtp-host">Serveur SMTP</label>
                      <input id="smtp-host" name="smtp_host" type="text" required autoComplete="off" />
                    </div>
                    <div className="admin-field-row">
                      <div className="admin-field">
                        <label htmlFor="smtp-port">Port</label>
                        <input id="smtp-port" name="smtp_port" type="number" min={1} max={65535} defaultValue={587} required />
                      </div>
                      <div className="admin-field">
                        <label htmlFor="smtp-security">Chiffrement</label>
                        <select id="smtp-security" name="smtp_security" defaultValue="starttls">
                          <option value="starttls">STARTTLS</option>
                          <option value="tls">TLS implicite</option>
                          <option value="none">Aucun chiffrement</option>
                        </select>
                      </div>
                    </div>
                    <div className="admin-field">
                      <label htmlFor="smtp-username">Utilisateur</label>
                      <input id="smtp-username" name="smtp_username" type="text" autoComplete="username" />
                    </div>
                  </Fragment>
                ) : (
                  <Fragment key="m365-connection">
                    <div className="admin-field">
                      <label htmlFor="m365-tenant">Identifiant de locataire (tenant)</label>
                      <input id="m365-tenant" name="m365_tenant_id" type="text" required autoComplete="off" />
                      <span className="admin-help">GUID du locataire ou nom de domaine du locataire.</span>
                    </div>
                    <div className="admin-field">
                      <label htmlFor="m365-client">Identifiant d’application (client ID)</label>
                      <input id="m365-client" name="m365_client_id" type="text" required autoComplete="off" />
                    </div>
                    <div className="admin-field">
                      <label htmlFor="m365-mailbox">Identité de boîte (facultatif)</label>
                      <input id="m365-mailbox" name="m365_mailbox" type="email" autoComplete="off" />
                    </div>
                  </Fragment>
                )}
              </fieldset>

              <fieldset className="admin-fieldset">
                <legend className="admin-fieldset-legend">Secret</legend>
                <p className="admin-secret-state">
                  <span className="admin-secret-label">Secret du transport</span>
                  <span>{email.secret_configured ? 'Enregistré (jamais affiché)' : 'Absent'}</span>
                </p>
                {emailTransport === 'smtp' ? (
                  <div className="admin-field" key="smtp-secret">
                    <label htmlFor="smtp-password">Mot de passe</label>
                    <input
                      id="smtp-password"
                      name="smtp_password"
                      type="password"
                      autoComplete="new-password"
                      aria-describedby="smtp-password-help"
                    />
                    <span className="admin-help" id="smtp-password-help">
                      Laisser vide pour conserver le mot de passe enregistré.
                    </span>
                  </div>
                ) : (
                  <div className="admin-field" key="m365-secret">
                    <label htmlFor="m365-secret">Secret de l’application</label>
                    <input
                      id="m365-secret"
                      name="m365_client_secret"
                      type="password"
                      autoComplete="new-password"
                      aria-describedby="m365-secret-help"
                    />
                    <span className="admin-help" id="m365-secret-help">
                      Laisser vide pour conserver le secret enregistré. Flux application uniquement :
                      aucun compte utilisateur ne se connecte.
                    </span>
                  </div>
                )}
              </fieldset>

              <fieldset className="admin-fieldset">
                <legend className="admin-fieldset-legend">Récupération et test</legend>
                <div className="admin-field">
                  <label htmlFor="email-recovery">Adresse de récupération</label>
                  <input id="email-recovery" name="recovery_email" type="email" autoComplete="email" />
                  <span className="admin-help" id="email-recovery-help">
                    Destinataire du mot de passe oublié. Le test d’envoi part vers l’adresse de
                    récupération utilisée par l’API.
                  </span>
                  <span className="admin-help">
                    Adresse de récupération : {email.recovery_email_configured ? 'enregistrée' : 'absente'}
                  </span>
                </div>
                <button
                  type="button"
                  className="button secondary"
                  disabled={!email.recovery_email_configured}
                  aria-describedby="email-test-help"
                  onClick={() => void submitEmailTest()}
                >
                  Tester l’envoi
                </button>
                <span className="admin-help" id="email-test-help">
                  {email.recovery_email_configured
                    ? 'Le test utilise la dernière configuration enregistrée.'
                    : 'Renseignez une adresse de récupération pour activer le test.'}
                </span>
              </fieldset>

              <details className="admin-advanced">
                <summary>Options avancées</summary>
                <div className="admin-field">
                  <label htmlFor="email-timeout">Délai d’envoi maximal (secondes)</label>
                  <input id="email-timeout" name="timeout_seconds" type="number" min={1} max={60} defaultValue={10} />
                </div>
                {emailTransport === 'smtp' && (
                  <div className="admin-field" key="smtp-advanced">
                    <label>
                      <input name="smtp_allow_plaintext" type="checkbox" />
                      {' '}Autoriser explicitement un envoi non chiffré
                    </label>
                    <span className="admin-help">
                      Requis quand « Aucun chiffrement » est sélectionné : sans cette confirmation,
                      le mot de passe ne serait jamais protégé.
                    </span>
                  </div>
                )}
              </details>

              <button type="submit" className="button primary admin-submit">
                Enregistrer l’email
              </button>
            </form>
          </div>
        </div>
      </div>
    )

    const systemFacts = [
      { label: 'Mode de déploiement', value: deploymentMode },
      { label: 'Backend TLS', value: status.tls_backend },
      { label: 'Nom TLS attendu', value: status.tls_hostname || 'Non configuré' },
      {
        label: 'Récupération de l’accès',
        value: status.recovery_enabled
          ? 'Active — SMTP et origine publique configurés'
          : 'Indisponible — SMTP ou origine publique non configuré',
      },
      { label: 'Version du logiciel', value: status.version },
    ]
    const systemPanel = (
      <>
        <div className="admin-panel">
          <div className="admin-panel-header">
            <p className="admin-eyebrow">Configuration</p>
            <h3 className="admin-panel-title">Mode et informations système</h3>
            <p className="admin-panel-copy">
              Lecture seule : ces valeurs proviennent de la configuration du déploiement.
            </p>
          </div>
          <div className="admin-panel-body">
            <dl className="admin-fact-grid">
              {systemFacts.map((fact) => (
                <div key={fact.label} className="admin-fact">
                  <dt>{fact.label}</dt>
                  <dd>{fact.value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </>
    )

    const accountPanel = (
      <div className="admin-grid admin-grid--2">
        <div className="admin-panel">
          <div className="admin-panel-header">
            <p className="admin-eyebrow">Sécurité</p>
            <h3 className="admin-panel-title">Résumé du compte</h3>
            <p className="admin-panel-copy">
              Compte administrateur unique : mot de passe, récupération et sessions.
            </p>
          </div>
          <div className="admin-panel-body">
            <dl className="admin-deflist">
              <div>
                <dt>Récupération de l’accès</dt>
                <dd>
                  {status.recovery_enabled
                    ? 'Active — SMTP et origine publique configurés'
                    : 'Indisponible — configuration ou origine publique incomplètes'}
                </dd>
              </div>
              <div>
                <dt>Session courante</dt>
                <dd>Expire le {status.session_expires_at ?? 'inconnue'}</dd>
              </div>
              <div>
                <dt>Règle du mot de passe</dt>
                <dd>{PASSWORD_HELP}</dd>
              </div>
            </dl>
          </div>
        </div>

        <div className="admin-panel">
          <div className="admin-panel-header">
            <p className="admin-eyebrow">Compte administrateur</p>
            <h3 className="admin-panel-title">Mot de passe</h3>
            <p className="admin-panel-copy">
              Après modification, toutes les sessions sont fermées : reconnectez-vous.
            </p>
          </div>
          <div className="admin-panel-body">
            <form onSubmit={(event) => void submitPasswordChange(event)}>
              <div className="admin-field">
                <label htmlFor="current-password">Mot de passe actuel</label>
                <input
                  id="current-password"
                  name="current_password"
                  type="password"
                  required
                  autoComplete="current-password"
                />
              </div>
              <div className="admin-field">
                <label htmlFor="new-password">Nouveau mot de passe</label>
                <input
                  id="new-password"
                  name="password"
                  type="password"
                  required
                  autoComplete="new-password"
                  aria-describedby="new-password-help"
                />
                <span className="admin-help" id="new-password-help">{PASSWORD_HELP}</span>
              </div>
              <button type="submit" className="button primary admin-submit">Changer le mot de passe</button>
            </form>
          </div>
        </div>

        <div className="admin-panel admin-panel--wide">
          <div className="admin-panel-header">
            <p className="admin-eyebrow">Sessions</p>
            <h3 className="admin-panel-title">Sessions actives</h3>
            <p className="admin-panel-copy">
              Liste des sessions administrateur ouvertes sur cette instance.
            </p>
          </div>
          <div className="admin-panel-body">
            <ul className="admin-session-list">
              {sessions.map((row) => (
                <li key={`${row.created_at}-${row.current ? 'current' : 'other'}`}>
                  <span className="admin-session-dates">{row.created_at} → {row.expires_at}</span>
                  {row.current && <span className="admin-badge">(courante)</span>}
                </li>
              ))}
              {sessions.length === 0 && <li className="admin-empty">Aucune session ouverte.</li>}
            </ul>
            <button type="button" className="button danger" onClick={() => void submitRevoke()}>
              Révoquer toutes les sessions
            </button>
          </div>
        </div>
      </div>
    )

    const panels: Record<TabId, ReactNode> = {
      certificates: certificatesPanel,
      email: emailPanel,
      system: systemPanel,
      account: accountPanel,
    }

    body = (
      <>
        {tablist}
        {statusStrip}
        <section
          key={activeTab}
          id={`admin-panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`admin-tab-${activeTab}`}
          className="admin-tabpanel"
        >
          <div className="admin-section-heading">
            <p className="admin-eyebrow">
              {TABS.find((tab) => tab.id === activeTab)?.eyebrow}
            </p>
            <h2>
              {activeTab === 'certificates' && 'Certificats TLS'}
              {activeTab === 'email' && 'Messagerie'}
              {activeTab === 'system' && 'Système'}
              {activeTab === 'account' && 'Compte'}
            </h2>
          </div>
          {panels[activeTab]}
        </section>
      </>
    )
  }

  return (
    <div className="admin-shell">
      {topbar}
      <main className="admin-main">
        {messages}
        {body}
      </main>
      {footer}
    </div>
  )
}

export default AdminApp
