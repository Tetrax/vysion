import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import AdminApp from './AdminApp'
import App from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  // La préférence de thème vit dans localStorage : on la remet à zéro pour que
  // chaque test démarre sur le même état (« système », sans attribut).
  window.localStorage.removeItem('vysion-theme')
  document.documentElement.removeAttribute('data-theme')
})

type Routes = Record<string, () => Response>

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch(routes: Routes) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    void init
    const url = typeof input === 'string' ? input : String(input)
    const handler = routes[url]
    if (!handler) throw new Error(`unexpected fetch ${url}`)
    return handler()
  })
}

const anonymousStatus = {
  setup_required: false,
  authenticated: false,
  csrf_token: null,
  session_expires_at: null,
  tls_backend: 'none',
  tls_hostname: null,
  recovery_enabled: false,
  version: '2.0.0',
}

const setupStatus = { ...anonymousStatus, setup_required: true }

const authenticatedStatus = {
  ...anonymousStatus,
  authenticated: true,
  csrf_token: 'csrf-value',
  session_expires_at: '2026-09-23T00:00:00+00:00',
}

const standaloneStatus = { ...authenticatedStatus, tls_backend: 'local', tls_hostname: 'vysion.example' }

const certificateInfo = {
  subject: 'CN = vysion.example',
  issuer: 'CN = vysion.example',
  not_after: '2026-10-22T00:00:00+00:00',
  sha256: 'a'.repeat(64),
  sans: ['vysion.example'],
  chain_length: 1,
  hostname: 'vysion.example',
}

const emptySessions = { sessions: [] }
const emptyCertificates = {
  managed: true,
  tls_backend: 'local',
  tls_hostname: 'vysion.example',
  active: null,
  staging: null,
  generations: [],
}

describe('administration Vysion', () => {
  it('shows the login form for an anonymous visitor', async () => {
    mockFetch({ '/api/admin/status': () => jsonResponse(anonymousStatus) })
    render(<AdminApp />)

    expect(await screen.findByLabelText('Mot de passe')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Se connecter' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Révoquer toutes les sessions' })).not.toBeInTheDocument()
  })

  it('runs the first-run setup and lands on the dashboard', async () => {
    let setupDone = false
    mockFetch({
      '/api/admin/status': () => jsonResponse(setupDone ? authenticatedStatus : setupStatus),
      '/api/admin/setup': () => {
        setupDone = true
        return jsonResponse({ csrf_token: 'csrf-value' }, 201)
      },
      '/api/admin/sessions': () => jsonResponse({ sessions: [{ created_at: 'a', expires_at: 'b', current: true }] }),
      '/api/admin/certificates': () => jsonResponse({ ...emptyCertificates, managed: false, tls_backend: 'none' }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByText('Configuration initiale')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Nouveau mot de passe administrateur'), 'a-first-admin-password')
    await user.click(screen.getByRole('button', { name: 'Créer le compte administrateur' }))

    expect(await screen.findByRole('button', { name: 'Révoquer toutes les sessions' })).toBeInTheDocument()
    expect(screen.getByText(/\(courante\)/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Se déconnecter' })).toBeInTheDocument()
  })

  it('offers recovery only when it is enabled server-side', async () => {
    mockFetch({ '/api/admin/status': () => jsonResponse({ ...anonymousStatus, recovery_enabled: true }) })
    render(<AdminApp />)

    expect(await screen.findByRole('button', { name: 'Recevoir un lien de récupération' })).toBeInTheDocument()
    expect(screen.getByLabelText('Jeton de récupération')).toBeInTheDocument()
  })

  it('validates a staged certificate and offers activation in standalone mode', async () => {
    let validationDone = false
    mockFetch({
      '/api/admin/status': () => jsonResponse(standaloneStatus),
      '/api/admin/sessions': () => jsonResponse(emptySessions),
      '/api/admin/certificates': () =>
        jsonResponse(validationDone ? { ...emptyCertificates, staging: certificateInfo } : emptyCertificates),
      '/api/admin/certificates/validate': () =>
        jsonResponse({ certificate: certificateInfo, ticket: { token: 'ticket-value', expires_in: 300 } }),
      '/api/admin/certificates/activate': () =>
        jsonResponse({ status: 'active', generation: 1, certificate: certificateInfo, served_sha256: 'a'.repeat(64) }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByText('Certificats TLS')).toBeInTheDocument()
    expect(screen.getByText('Aucun certificat actif.')).toBeInTheDocument()

    validationDone = true
    const certificateFile = new File(['-----BEGIN CERTIFICATE-----'], 'fullchain.pem', { type: 'application/x-pem-file' })
    await user.upload(screen.getByLabelText(/Certificat \(PEM complet/), certificateFile)
    await user.click(screen.getByRole('button', { name: 'Valider le certificat' }))

    expect(await screen.findByRole('button', { name: 'Activer le certificat' })).toBeInTheDocument()
    expect(screen.getByText(/CN = vysion.example/)).toBeInTheDocument()
    const validateCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) =>
      String(input).includes('/certificates/validate'),
    )
    expect(validateCall).toBeDefined()
    expect((validateCall?.[1]?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-value')

    await user.click(screen.getByRole('button', { name: 'Activer le certificat' }))
    expect(await screen.findByText('Certificat activé (génération 1)')).toBeInTheDocument()
  })

  it('keeps the anonymous audit flow completely free of admin calls', () => {
    vi.spyOn(globalThis, 'fetch')
    render(<App />)

    const adminCalls = vi.mocked(globalThis.fetch).mock.calls.filter(([input]) =>
      String(input).includes('/api/admin'),
    )
    expect(adminCalls).toHaveLength(0)
    expect(screen.getByLabelText('Configuration FortiGate')).toBeInTheDocument()
  })
})

describe('interface d’administration Vysion', () => {
  const authenticatedRoutes: Routes = {
    '/api/admin/status': () => jsonResponse(authenticatedStatus),
    '/api/admin/sessions': () => jsonResponse(emptySessions),
    '/api/admin/certificates': () => jsonResponse(emptyCertificates),
  }

  it('organise l’administration authentifiée en quatre sections', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByRole('heading', { name: 'Vue d’ensemble' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Certificats TLS' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Système' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Compte' })).toBeInTheDocument()

    const nav = screen.getByRole('navigation', { name: 'Sections d’administration' })
    expect(within(nav).getAllByRole('link')).toHaveLength(4)
    expect(within(nav).getByRole('link', { name: 'Vue d’ensemble' })).toHaveAttribute('aria-current', 'page')

    await user.click(within(nav).getByRole('link', { name: 'Compte' }))
    expect(within(nav).getByRole('link', { name: 'Compte' })).toHaveAttribute('aria-current', 'page')
    expect(within(nav).getByRole('link', { name: 'Vue d’ensemble' })).not.toHaveAttribute('aria-current')
  })

  it('affiche l’identité, le retour à l’audit, le thème et la déconnexion', async () => {
    mockFetch(authenticatedRoutes)
    render(<AdminApp />)

    expect(await screen.findByText('Vysion')).toBeInTheDocument()
    expect(screen.getByText('Administration')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Retour à l’audit' })).toHaveAttribute('href', '/')
    expect(screen.getByRole('button', { name: 'Thème : système' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Se déconnecter' })).toBeInTheDocument()
    expect(screen.getByText('Vysion — administration privée')).toBeInTheDocument()
  })

  it('tient chaque action essentielle à un seul endroit', async () => {
    mockFetch({
      '/api/admin/status': () => jsonResponse(standaloneStatus),
      '/api/admin/sessions': () => jsonResponse(emptySessions),
      '/api/admin/certificates': () => jsonResponse(emptyCertificates),
    })
    render(<AdminApp />)

    expect(await screen.findByRole('heading', { name: 'Certificats TLS' })).toBeInTheDocument()
    expect(screen.getAllByText('Retour à l’audit')).toHaveLength(1)
    expect(screen.getAllByText('Se déconnecter')).toHaveLength(1)
    expect(screen.getAllByText('Révoquer toutes les sessions')).toHaveLength(1)
    expect(screen.getAllByText('Changer le mot de passe')).toHaveLength(1)
    expect(screen.getAllByText('Valider le certificat')).toHaveLength(1)
  })

  it('explique que le proxy hôte termine le TLS en mode proxy', async () => {
    mockFetch(authenticatedRoutes)
    render(<AdminApp />)

    expect(await screen.findByText('Le TLS est géré par le proxy hôte')).toBeInTheDocument()
    expect(screen.getByText(/Vysion n’importe ni n’active aucun certificat dans ce mode/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Valider le certificat' })).not.toBeInTheDocument()
    expect(screen.getByText('Géré par le proxy hôte')).toBeInTheDocument()
  })

  it('présente le contrat du mot de passe à la configuration initiale', async () => {
    mockFetch({ '/api/admin/status': () => jsonResponse(setupStatus) })
    render(<AdminApp />)

    expect(await screen.findByText('Zone d’administration privée')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Configuration initiale' })).toBeInTheDocument()
    expect(screen.getByText('12 à 1 024 octets UTF-8.')).toBeInTheDocument()
    expect(screen.getByLabelText('Nouveau mot de passe administrateur')).toHaveAttribute(
      'aria-describedby',
      'setup-password-help',
    )
    expect(screen.queryByRole('navigation', { name: 'Sections d’administration' })).not.toBeInTheDocument()
  })

  it('applique et mémorise le thème clair, sombre puis système', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    const toggle = await screen.findByRole('button', { name: 'Thème : système' })
    expect(document.documentElement).not.toHaveAttribute('data-theme')

    await user.click(toggle)
    expect(screen.getByRole('button', { name: 'Thème : clair' })).toBeInTheDocument()
    expect(document.documentElement).toHaveAttribute('data-theme', 'light')
    expect(window.localStorage.getItem('vysion-theme')).toBe('light')

    await user.click(screen.getByRole('button', { name: 'Thème : clair' }))
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
    expect(window.localStorage.getItem('vysion-theme')).toBe('dark')

    await user.click(screen.getByRole('button', { name: 'Thème : sombre' }))
    expect(document.documentElement).not.toHaveAttribute('data-theme')
    expect(window.localStorage.getItem('vysion-theme')).toBeNull()
  })

  it('recharge la préférence de thème enregistrée localement', async () => {
    window.localStorage.setItem('vysion-theme', 'dark')
    mockFetch(authenticatedRoutes)
    render(<AdminApp />)

    expect(await screen.findByRole('button', { name: 'Thème : sombre' })).toBeInTheDocument()
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
  })

  it('change le mot de passe avec le jeton CSRF et annonce le résultat', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/password': () => jsonResponse({ status: 'password_updated' }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('heading', { name: 'Compte' })
    await user.type(screen.getByLabelText('Mot de passe actuel'), 'current-admin-password')
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'a-new-admin-password')
    await user.click(screen.getByRole('button', { name: 'Changer le mot de passe' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Mot de passe modifié')
    const call = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input) === '/api/admin/password')
    expect(call).toBeDefined()
    expect((call?.[1]?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-value')
  })

  it('révoque les sessions depuis la section Compte', async () => {
    let revoked = false
    mockFetch({
      '/api/admin/status': () => jsonResponse(authenticatedStatus),
      '/api/admin/sessions': () => jsonResponse(
        revoked
          ? { sessions: [{ created_at: 'a', expires_at: 'b', current: false }] }
          : { sessions: [{ created_at: 'a', expires_at: 'b', current: true }] },
      ),
      '/api/admin/certificates': () => jsonResponse(emptyCertificates),
      '/api/admin/sessions/revoke': () => {
        revoked = true
        return jsonResponse({ revoked: 1 })
      },
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByText('(courante)')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Révoquer toutes les sessions' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Toutes les sessions ont été révoquées')
    const call = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input) === '/api/admin/sessions/revoke')
    expect((call?.[1]?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-value')
  })
})
