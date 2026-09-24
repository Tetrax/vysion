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

const emptyEmail = {
  configured: false,
  transport: null,
  provenance: null,
  secret_configured: false,
  recovery_email_configured: false,
  recovery_enabled: false,
}

const configuredEmail = {
  ...emptyEmail,
  configured: true,
  transport: 'microsoft365',
  secret_configured: true,
  recovery_email_configured: true,
}

const authenticatedRoutes: Routes = {
  '/api/admin/status': () => jsonResponse(authenticatedStatus),
  '/api/admin/sessions': () => jsonResponse(emptySessions),
  '/api/admin/certificates': () => jsonResponse(emptyCertificates),
  '/api/admin/email': () => jsonResponse(emptyEmail),
}

const TAB_LABELS = ['Certificats', 'Messagerie', 'Système', 'Compte']

async function openTab(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole('tab', { name: label }))
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
      '/api/admin/email': () => jsonResponse(emptyEmail),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByText('Configuration initiale')).toBeInTheDocument()
    // Tant que la session n'existe pas, aucun onglet métier n'est proposé.
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('Nouveau mot de passe administrateur'), 'a-first-admin-password')
    await user.click(screen.getByRole('button', { name: 'Créer le compte administrateur' }))

    expect(await screen.findByRole('tablist', { name: 'Sections d’administration' })).toBeInTheDocument()
    await openTab(user, 'Compte')
    expect(screen.getByRole('button', { name: 'Révoquer toutes les sessions' })).toBeInTheDocument()
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
      '/api/admin/email': () => jsonResponse(emptyEmail),
      '/api/admin/certificates/validate': () =>
        jsonResponse({ certificate: certificateInfo, ticket: { token: 'ticket-value', expires_in: 300 } }),
      '/api/admin/certificates/activate': () =>
        jsonResponse({ status: 'active', generation: 1, certificate: certificateInfo, served_sha256: 'a'.repeat(64) }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByRole('heading', { name: 'Certificats TLS' })).toBeInTheDocument()
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
  it('présente quatre onglets ARIA et un seul panneau métier à la fois', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    const tablist = await screen.findByRole('tablist', { name: 'Sections d’administration' })
    const tabs = within(tablist).getAllByRole('tab')
    expect(tabs.map((tab) => tab.textContent)).toEqual(TAB_LABELS)

    expect(tabs[0]).toHaveAttribute('id', 'admin-tab-certificates')
    expect(tabs[0]).toHaveAttribute('aria-controls', 'admin-panel-certificates')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveAttribute('tabindex', '0')
    expect(tabs[1]).toHaveAttribute('aria-selected', 'false')
    expect(tabs[1]).toHaveAttribute('tabindex', '-1')

    expect(screen.getAllByRole('tabpanel')).toHaveLength(1)
    const certificatesPanel = screen.getByRole('tabpanel')
    expect(certificatesPanel).toHaveAttribute('id', 'admin-panel-certificates')
    expect(certificatesPanel).toHaveAttribute('aria-labelledby', 'admin-tab-certificates')
    expect(within(certificatesPanel).getByRole('heading', { name: 'Certificats TLS' })).toBeInTheDocument()

    await user.click(tabs[1])
    expect(screen.getAllByRole('tabpanel')).toHaveLength(1)
    expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'admin-panel-email')
    expect(tabs[1]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[1]).toHaveAttribute('tabindex', '0')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'false')
    expect(tabs[0]).toHaveAttribute('tabindex', '-1')
    expect(screen.queryByRole('heading', { name: 'Certificats TLS' })).not.toBeInTheDocument()

    await user.click(tabs[3])
    expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'admin-panel-account')
    expect(screen.queryByRole('heading', { name: 'Messagerie' })).not.toBeInTheDocument()
  })

  it('navigue entre les onglets au clavier (Gauche, Droite, Home, End)', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    const tablist = await screen.findByRole('tablist', { name: 'Sections d’administration' })
    const tabs = within(tablist).getAllByRole('tab')
    tabs[0].focus()

    await user.keyboard('{ArrowRight}')
    expect(tabs[1]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[1]).toHaveFocus()
    expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'admin-panel-email')

    await user.keyboard('{ArrowLeft}')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveFocus()
    expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'admin-panel-certificates')

    await user.keyboard('{End}')
    expect(tabs[3]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[3]).toHaveFocus()
    expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'admin-panel-account')

    await user.keyboard('{Home}')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveFocus()

    // La barre droite referme la boucle depuis le dernier onglet.
    await user.keyboard('{End}{ArrowRight}')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveFocus()
  })

  it('ne s’appuie plus sur des ancres de défilement', async () => {
    mockFetch(authenticatedRoutes)
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    expect(document.querySelectorAll('a[href^="#"]')).toHaveLength(0)
    expect(screen.queryByRole('navigation', { name: 'Sections d’administration' })).not.toBeInTheDocument()
    expect(screen.queryByText('Vue d’ensemble')).not.toBeInTheDocument()
  })

  it('garde un bandeau de statuts commun au-dessus du panneau actif', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    const strip = await screen.findByRole('region', { name: 'État courant' })
    expect(within(strip).getByText('Version')).toBeInTheDocument()
    expect(within(strip).getByText('2.0.0')).toBeInTheDocument()
    expect(within(strip).getByText('TLS')).toBeInTheDocument()
    expect(within(strip).getByText('Session')).toBeInTheDocument()
    expect(within(strip).getByText('Certificat')).toBeInTheDocument()
    // Le bandeau n'est pas un cinquième onglet.
    expect(within(strip).queryByRole('tab')).not.toBeInTheDocument()

    await openTab(user, 'Messagerie')
    expect(screen.getByRole('region', { name: 'État courant' })).toBeInTheDocument()
    expect(screen.getByRole('tabpanel')).toHaveAttribute('id', 'admin-panel-email')
  })

  it('tient chaque action essentielle à un seul endroit, dans son panneau', async () => {
    mockFetch({
      '/api/admin/status': () => jsonResponse(standaloneStatus),
      '/api/admin/sessions': () => jsonResponse(emptySessions),
      '/api/admin/certificates': () => jsonResponse(emptyCertificates),
      '/api/admin/email': () => jsonResponse(emptyEmail),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    // Actions globales : jamais dupliquées, toujours présentes.
    expect(screen.getAllByText('Retour à l’audit')).toHaveLength(1)
    expect(screen.getAllByText('Se déconnecter')).toHaveLength(1)

    const actionsByTab: Record<string, string[]> = {
      Certificats: ['Valider le certificat'],
      Messagerie: ["Enregistrer l’email", 'Tester l’envoi'],
      Système: [],
      Compte: ['Changer le mot de passe', 'Révoquer toutes les sessions'],
    }

    for (const label of TAB_LABELS) {
      await openTab(user, label)
      for (const [otherLabel, actions] of Object.entries(actionsByTab)) {
        for (const action of actions) {
          const matches = screen.queryAllByText(action)
          if (otherLabel === label) {
            expect(matches, `${action} devrait être visible dans ${label}`).toHaveLength(1)
          } else {
            expect(matches, `${action} ne devrait pas exister hors de ${otherLabel}`).toHaveLength(0)
          }
        }
      }
    }
  })

  it('explique que le proxy hôte termine le TLS en mode proxy', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByText('Le TLS est géré par le proxy hôte')).toBeInTheDocument()
    expect(screen.getByText(/Vysion n’importe ni n’active aucun certificat dans ce mode/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Valider le certificat' })).not.toBeInTheDocument()
    expect(screen.getByText('Géré par le proxy hôte')).toBeInTheDocument()

    await openTab(user, 'Système')
    expect(screen.getByText(/TLS géré par le proxy hôte/)).toBeInTheDocument()
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
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
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

  it('change le mot de passe avec le jeton CSRF et annonce le résultat', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/password': () => jsonResponse({ status: 'password_updated' }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Compte')
    await user.type(screen.getByLabelText('Mot de passe actuel'), 'current-admin-password')
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'a-new-admin-password')
    await user.click(screen.getByRole('button', { name: 'Changer le mot de passe' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Mot de passe modifié')
    const call = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input) === '/api/admin/password')
    expect(call).toBeDefined()
    expect((call?.[1]?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-value')
  })

  it('révoque les sessions depuis l’onglet Compte', async () => {
    let revoked = false
    mockFetch({
      '/api/admin/status': () => jsonResponse(authenticatedStatus),
      '/api/admin/sessions': () => jsonResponse(
        revoked
          ? { sessions: [{ created_at: 'a', expires_at: 'b', current: false }] }
          : { sessions: [{ created_at: 'a', expires_at: 'b', current: true }] },
      ),
      '/api/admin/certificates': () => jsonResponse(emptyCertificates),
      '/api/admin/email': () => jsonResponse(emptyEmail),
      '/api/admin/sessions/revoke': () => {
        revoked = true
        return jsonResponse({ revoked: 1 })
      },
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Compte')

    expect(await screen.findByText('(courante)')).toBeInTheDocument()
    expect(screen.getByText('1 session ouverte')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Révoquer toutes les sessions' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Toutes les sessions ont été révoquées')
    const call = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input) === '/api/admin/sessions/revoke')
    expect((call?.[1]?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-value')
  })

  it('affiche une liste de sessions vide sans casser les actions', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Compte')
    expect(screen.getByText('Aucune session ouverte.')).toBeInTheDocument()
    expect(screen.getByText('0 sessions ouvertes')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Révoquer toutes les sessions' })).toBeEnabled()
  })

  it('ouvre l’onglet de certificats en mode helper comme en standalone', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/status': () =>
        jsonResponse({ ...authenticatedStatus, tls_backend: 'helper', tls_hostname: 'vysion.example' }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    expect(await screen.findByRole('heading', { name: 'Certificats TLS' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Valider le certificat' })).toBeInTheDocument()
    expect(screen.queryByText('Le TLS est géré par le proxy hôte')).not.toBeInTheDocument()
    expect(screen.getByText('Helper')).toBeInTheDocument()

    await openTab(user, 'Système')
    expect(screen.getByText(/Helper — Vysion pilote le Nginx hôte/)).toBeInTheDocument()
  })

  it('matérialise le parcours validation → contrôles → activation', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/status': () => jsonResponse(standaloneStatus),
      '/api/admin/certificates/validate': () =>
        jsonResponse({ certificate: certificateInfo, ticket: { token: 'ticket-value', expires_in: 300 } }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    const steps = await screen.findByRole('list', { name: 'Parcours du certificat' })
    const labels = within(steps).getAllByRole('listitem').map((item) => item.textContent ?? '')
    expect(labels).toHaveLength(3)
    expect(labels[0]).toContain('Valider')
    expect(labels[1]).toContain('Contrôles')
    expect(labels[2]).toContain('Activer')
    // Tant que rien n'est validé, l'activation reste annoncée comme en attente.
    expect(labels[2]).toContain('En attente')
    expect(screen.queryByRole('button', { name: 'Activer le certificat' })).not.toBeInTheDocument()

    const certificateFile = new File(['-----BEGIN CERTIFICATE-----'], 'fullchain.pem', { type: 'application/x-pem-file' })
    await user.upload(screen.getByLabelText(/Certificat \(PEM complet/), certificateFile)
    await user.click(screen.getByRole('button', { name: 'Valider le certificat' }))

    expect(await screen.findByRole('button', { name: 'Activer le certificat' })).toBeInTheDocument()
    const afterValidation = within(screen.getByRole('list', { name: 'Parcours du certificat' }))
      .getAllByRole('listitem')
      .map((item) => item.textContent ?? '')
    expect(afterValidation[1]).toContain('Contrôles réussis')
    expect(afterValidation[2]).toContain('Prêt')
  })

  it('structure la Messagerie en groupes lisibles avec statut textuel', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/email': () => jsonResponse(configuredEmail),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Messagerie')

    expect(screen.getByRole('heading', { name: 'Messagerie' })).toBeInTheDocument()
    // Statut textuel, sans couleur seule.
    expect(screen.getByText('Configuration complète — Microsoft 365')).toBeInTheDocument()
    expect(screen.getByText('Enregistré (jamais affiché)')).toBeInTheDocument()

    // Sélecteur de transport mis en avant.
    const transport = screen.getByLabelText('Comment voulez-vous envoyer les courriels ?')
    expect(transport).toBeInTheDocument()

    // Groupes de champs.
    expect(screen.getByRole('group', { name: 'Communs' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Connexion et identité' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Secret' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Récupération et test' })).toBeInTheDocument()

    // Options avancées repliables : timeout + confirmation plaintext.
    const advanced = screen.getByText('Options avancées').closest('details')
    expect(advanced).not.toBeNull()
    expect(within(advanced as HTMLElement).getByLabelText(/Délai d’envoi maximal/)).toBeInTheDocument()

    // Le test d'envoi est explicitement relié à l'adresse de récupération.
    expect(screen.getByText(/adresse de récupération utilisée par l’API/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Tester l’envoi' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Enregistrer l’email' })).toBeInTheDocument()

    // Le secret n'est jamais affiché ni prérempli.
    expect(screen.getByLabelText(/Secret de l’application/)).toHaveValue('')
    expect(screen.queryByLabelText('Serveur SMTP')).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('graph-write')
  })

  it('annonce une Messagerie incomplète tant que le transport n’est pas utilisable', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/email': () => jsonResponse(emptyEmail),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Messagerie')

    expect(screen.getByText('Configuration incomplète')).toBeInTheDocument()
    expect(screen.getByText('Adresse de récupération : absente')).toBeInTheDocument()
    // Sans adresse de récupération, l'API refuserait le test : le bouton l'annonce.
    expect(screen.getByRole('button', { name: 'Tester l’envoi' })).toBeDisabled()
    expect(screen.getByText(/Renseignez une adresse de récupération/)).toBeInTheDocument()
    expect(screen.getByLabelText('Comment voulez-vous envoyer les courriels ?')).toHaveValue('smtp')
  })

  it('isole les champs des deux transports en cas de bascule', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/email': () => jsonResponse(emptyEmail),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Messagerie')
    // The SMTP shape comes first and its port carries its default value.
    expect(screen.getByLabelText('Port')).toHaveValue(587)

    await user.selectOptions(screen.getByLabelText('Comment voulez-vous envoyer les courriels ?'), 'microsoft365')

    // The Microsoft 365 fields must mount empty: React must not reuse the
    // SMTP inputs (the port default would otherwise leak into the client ID,
    // and a typed host into the tenant field).
    expect(screen.getByLabelText(/client ID/i)).toHaveValue('')
    expect(screen.getByLabelText(/locataire/)).toHaveValue('')
    expect(screen.getByLabelText(/boîte/)).toHaveValue('')
    expect(screen.getByLabelText(/Secret de l’application/)).toHaveValue('')

    await user.selectOptions(screen.getByLabelText('Comment voulez-vous envoyer les courriels ?'), 'smtp')

    // And back: the SMTP defaults are pristine, no Microsoft 365 leftovers.
    expect(screen.getByLabelText('Port')).toHaveValue(587)
    expect(screen.getByLabelText('Serveur SMTP')).toHaveValue('')
    expect(screen.queryByLabelText(/Secret de l’application/)).not.toBeInTheDocument()
  })

  it('conserve les contrats d’enregistrement email (secrets vides = conservation)', async () => {
    const saved: { body: Record<string, unknown> | null } = { body: null }
    const routes: Routes = {
      ...authenticatedRoutes,
      '/api/admin/email': () => jsonResponse(configuredEmail),
      '/api/admin/email/test': () => jsonResponse({ status: 'sent', transport: 'microsoft365' }),
    }
    mockFetch(routes)
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Messagerie')

    const transport = screen.getByLabelText('Comment voulez-vous envoyer les courriels ?')
    expect(transport).toHaveValue('microsoft365')

    await user.type(screen.getByLabelText('Adresse d’expédition'), 'no-reply@vysion.example')
    await user.type(screen.getByLabelText(/Identifiant de locataire/), '11111111-1111-1111-1111-111111111111')
    await user.type(screen.getByLabelText(/Identifiant d’application/), '22222222-2222-2222-2222-222222222222')

    const putCall = vi.fn(async () => {
      return jsonResponse(configuredEmail)
    })
    vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : String(input)
      if (url === '/api/admin/email' && init?.method === 'PUT') {
        saved.body = JSON.parse(String(init.body)) as Record<string, unknown>
        return putCall()
      }
      const handler = routes[url]
      if (!handler) throw new Error(`unexpected fetch ${url}`)
      return handler()
    })

    await user.click(screen.getByRole('button', { name: 'Enregistrer l’email' }))
    await screen.findByText('Configuration email enregistrée')

    expect(saved.body).not.toBeNull()
    expect(saved.body?.transport).toBe('microsoft365')
    expect(saved.body?.m365_client_secret).toBe('')
    expect(saved.body?.smtp_password).toBe('')
    expect(saved.body?.timeout_seconds).toBe(10)

    await user.click(screen.getByRole('button', { name: 'Tester l’envoi' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Email de test envoyé via microsoft365')
  })

  it('résume le système avec les seules informations de Vysion', async () => {
    mockFetch(authenticatedRoutes)
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Système')

    const panel = screen.getByRole('tabpanel')
    expect(within(panel).getByRole('heading', { name: 'Système' })).toBeInTheDocument()
    expect(within(panel).getByText('Mode de déploiement')).toBeInTheDocument()
    expect(within(panel).getByText('Backend TLS')).toBeInTheDocument()
    expect(within(panel).getByText('Récupération de l’accès')).toBeInTheDocument()
    expect(within(panel).getByText('Version du logiciel')).toBeInTheDocument()
    expect(within(panel).getByText('2.0.0')).toBeInTheDocument()
    // Aucune fonctionnalité absente de Vysion n'est recopiée de la référence.
    expect(screen.queryByText(/Trivy/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Fortinet/)).not.toBeInTheDocument()
  })

  it('résume le compte et ses actions dans l’onglet Compte', async () => {
    mockFetch({
      ...authenticatedRoutes,
      '/api/admin/sessions': () =>
        jsonResponse({ sessions: [{ created_at: 'a', expires_at: 'b', current: true }] }),
    })
    const user = userEvent.setup()
    render(<AdminApp />)

    await screen.findByRole('tablist', { name: 'Sections d’administration' })
    await openTab(user, 'Compte')

    expect(screen.getByRole('heading', { name: 'Compte' })).toBeInTheDocument()
    expect(screen.getByText('Sessions actives')).toBeInTheDocument()
    expect(screen.getByText('1 session ouverte')).toBeInTheDocument()
    expect(screen.getByText('Récupération de l’accès')).toBeInTheDocument()
    expect(screen.getByText('Indisponible — configuration ou origine publique incomplètes')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Changer le mot de passe' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Révoquer toutes les sessions' })).toBeInTheDocument()
  })
})
