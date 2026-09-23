import { FormEvent, useCallback, useEffect, useState } from 'react'
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

function AdminApp() {
  const [status, setStatus] = useState<AdminStatus | null>(null)
  const [csrf, setCsrf] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [sessions, setSessions] = useState<SessionRow[]>([])
  const [certificates, setCertificates] = useState<CertificatesStatus | null>(null)
  const [validation, setValidation] = useState<Validation | null>(null)

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
        const [listResponse, certificatesResponse] = await Promise.all([
          fetch('/api/admin/sessions'),
          fetch('/api/admin/certificates'),
        ])
        if (listResponse.ok) {
          const payload = (await listResponse.json()) as { sessions: SessionRow[] }
          setSessions(payload.sessions)
        }
        if (certificatesResponse.ok) {
          setCertificates((await certificatesResponse.json()) as CertificatesStatus)
        }
      } else {
        setCsrf('')
        setSessions([])
        setCertificates(null)
      }
    } catch {
      setError('API administrateur injoignable')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

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

  if (!status) {
    return <main className="admin-page"><p>Chargement…</p></main>
  }

  const standalone = status.tls_backend === 'local'

  if (!status.authenticated) {
    return (
      <main className="admin-page">
        <h1>Administration Vysion</h1>
        {error && <p role="alert">{error}</p>}
        {message && <p role="status">{message}</p>}
        {status.setup_required ? (
          <form onSubmit={(event) => void submitCredentials(event, '/api/admin/setup')}>
            <h2>Configuration initiale</h2>
            <label htmlFor="setup-password">Nouveau mot de passe administrateur</label>
            <input id="setup-password" name="password" type="password" required autoComplete="new-password" />
            <button type="submit">Créer le compte administrateur</button>
          </form>
        ) : (
          <form onSubmit={(event) => void submitCredentials(event, '/api/admin/login')}>
            <h2>Connexion</h2>
            <label htmlFor="login-password">Mot de passe</label>
            <input id="login-password" name="password" type="password" required autoComplete="current-password" />
            <button type="submit">Se connecter</button>
          </form>
        )}
        {!status.setup_required && status.recovery_enabled && (
          <section>
            <h2>Récupération de l’accès</h2>
            <button type="button" onClick={() => void submitRecoveryRequest()}>
              Recevoir un lien de récupération
            </button>
            <form onSubmit={(event) => void submitRecoveryConfirm(event)}>
              <label htmlFor="recovery-token">Jeton de récupération</label>
              <input id="recovery-token" name="token" type="text" required />
              <label htmlFor="recovery-password">Nouveau mot de passe</label>
              <input id="recovery-password" name="password" type="password" required autoComplete="new-password" />
              <button type="submit">Utiliser le jeton</button>
            </form>
          </section>
        )}
        <p><a href="/">Retour à l’audit</a></p>
      </main>
    )
  }

  return (
    <main className="admin-page">
      <h1>Administration Vysion</h1>
      <p>
        Version {status.version} — TLS {status.tls_backend}
        {status.tls_hostname ? ` (${status.tls_hostname})` : ''} — session jusqu’à{' '}
        {status.session_expires_at ?? 'inconnue'}
      </p>
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}

      <section>
        <h2>Sessions</h2>
        <ul>
          {sessions.map((row) => (
            <li key={`${row.created_at}-${row.current ? 'current' : 'other'}`}>
              {row.created_at} → {row.expires_at}
              {row.current ? ' (courante)' : ''}
            </li>
          ))}
        </ul>
        <button type="button" onClick={() => void submitRevoke()}>Révoquer toutes les sessions</button>
      </section>

      <section>
        <h2>Mot de passe</h2>
        <form onSubmit={(event) => void submitPasswordChange(event)}>
          <label htmlFor="current-password">Mot de passe actuel</label>
          <input id="current-password" name="current_password" type="password" required autoComplete="current-password" />
          <label htmlFor="new-password">Nouveau mot de passe</label>
          <input id="new-password" name="password" type="password" required autoComplete="new-password" />
          <button type="submit">Changer le mot de passe</button>
        </form>
      </section>

      <section>
        <h2>Certificats TLS</h2>
        {!standalone && <p>Certificats gérés par le réseau hôte (mode proxy).</p>}
        {standalone && certificates && (
          <>
            <h3>Actif</h3>
            {certificates.active ? (
              <p>
                Génération {certificates.active.number} — {certificates.active.subject} — expire le{' '}
                {certificates.active.not_after} — SHA-256 {shortFingerprint(certificates.active.sha256)}…
              </p>
            ) : (
              <p>Aucun certificat actif.</p>
            )}
            <h3>Candidat en attente</h3>
            {certificates.staging && (
              <p>
                {certificates.staging.subject} — expire le {certificates.staging.not_after} — SHA-256{' '}
                {shortFingerprint(certificates.staging.sha256)}…
              </p>
            )}
            <form onSubmit={(event) => void submitValidation(event)}>
              <label htmlFor="certificate-file">Certificat (PEM complet ou archive PKCS#12)</label>
              <input id="certificate-file" name="certificate" type="file" />
              <label htmlFor="key-file">Clé privée (PEM, facultatif pour une archive)</label>
              <input id="key-file" name="private_key" type="file" />
              <label htmlFor="passphrase-input">Passphrase de l’archive (facultative)</label>
              <input id="passphrase-input" name="passphrase" type="password" autoComplete="off" />
              <button type="submit">Valider le certificat</button>
            </form>
            {validation && (
              <div>
                <p>
                  {validation.certificate.subject} — expire le {validation.certificate.not_after} — chaîne de{' '}
                  {validation.certificate.chain_length} certificat(s) — hostname {validation.certificate.hostname}
                </p>
                <button type="button" onClick={() => void submitActivation()}>Activer le certificat</button>
              </div>
            )}
            <h3>Générations</h3>
            <ul>
              {certificates.generations.map((generation) => (
                <li key={generation.number}>
                  #{generation.number}
                  {generation.is_active ? ' (actif)' : ''} — expire le {generation.not_after}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <p><a href="/">Retour à l’audit</a> — <button type="button" onClick={() => void submitLogout()}>Se déconnecter</button></p>
    </main>
  )
}

export default AdminApp
