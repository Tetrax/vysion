import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import AdminApp from './AdminApp'
import App from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
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
