import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import { VYSION_VERSION } from './buildInfo'


afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('Vysion guided workflow', () => {
  it('displays the shared release version', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: `Vysion ${VYSION_VERSION}` })).toBeInTheDocument()
  })

  it('previews the selected file before showing equipment context', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          hostname: 'preview-lab.example',
          model: '60E',
          firmware_version: '7.2.9',
          serial_number: null,
          interfaces: [
            { name: 'wan1', address: '192.0.2.10 255.255.255.0', role: 'wan', allowaccess: ['ping'] },
          ],
          zones: [{ name: 'internet', interfaces: ['wan1'] }],
          sdwan_zones: [],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<App />)

    await user.upload(
      screen.getByLabelText('Configuration FortiGate'),
      new File(['config system global\nend'], 'preview.conf', { type: 'text/plain' }),
    )

    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/api/audits/preview',
      expect.objectContaining({ method: 'POST', body: expect.any(FormData) }),
    )
    expect(await screen.findByText('preview-lab.example')).toBeInTheDocument()
    expect(screen.getByText('60E')).toBeInTheDocument()
    expect(screen.getByText('7.2.9')).toBeInTheDocument()
    expect(screen.getByText('internet')).toBeInTheDocument()
  })

  it('uses simple confirmation checkboxes and omits unconfirmed context', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({
        hostname: 'lab', model: '60E', firmware_version: '7.2.9', serial_number: null,
        interfaces: [{ name: 'wan1', role: 'wan' }], zones: [], sdwan_zones: [],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2', expires_at: '2026-08-12T12:01:00Z',
        context: { ha: null, mpls: false, utm_license: true, operator_provenance: { source: 'operator-form' } },
        fortiguard: { status: 'UNKNOWN', detail: 'fixture' }, findings: [],
      }), { status: 201, headers: { 'Content-Type': 'application/json' } }))
    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('lab')

    expect(screen.getByRole('checkbox', { name: 'HA présent' })).not.toBeChecked()
    expect(screen.queryByLabelText('Opérateur')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Provenance licence UTM')).not.toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: 'Licence UTM active' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const auditCall = vi.mocked(globalThis.fetch).mock.calls[1]
    const body = (auditCall[1] as RequestInit).body as FormData
    expect(body.has('ha_context')).toBe(false)
    expect(body.has('mpls_context')).toBe(false)
    expect(body.get('utm_license')).toBe('true')
    expect(body.get('utm_license_status')).toBe('active')
  })

  it('summarizes, groups, orders and filters findings without exposing details', async () => {
    const user = userEvent.setup()
    const findings = [
      { control_id: 'SYS-PASS', title: 'Conforme', status: 'PASS', category: 'system', severity: 'low', applicability: 'applicable', message: 'ok', affected_objects: [] },
      { control_id: 'UTM-NA', title: 'Sans objet', status: 'NOT_APPLICABLE', category: 'utm', severity: 'info', applicability: 'not_applicable', message: 'n/a', affected_objects: [] },
      { control_id: 'FW-UNK', title: 'Incertain', status: 'UNKNOWN', category: 'firewall', severity: 'medium', applicability: 'unknown', message: 'unknown', affected_objects: [] },
      { control_id: 'NET-FAIL', title: 'Violation', status: 'FAIL', category: 'network', severity: 'critical', applicability: 'applicable', message: 'fail', affected_objects: [{ name: 'wan1', object_type: 'interface' }], evidence: ['SECRET DETAIL'] },
      { control_id: 'WIFI-PASS', title: 'Wi-Fi conforme', status: 'PASS', category: 'wifi', severity: 'low', applicability: 'applicable', message: 'ok', affected_objects: [] },
    ]
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ hostname: 'lab', model: '60E', firmware_version: '7.2.9', interfaces: [], zones: [], sdwan_zones: [] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2', expires_at: '2026-08-12T12:01:00Z', context: {}, equipment: { hostname: 'parsed-fw', model: '100F', firmware_version: '7.4.3', interface_names: ['wan1', 'lan1'], zone_names: ['internet'], sdwan_zone_names: ['sdwan-public'], interface_zone_relations: ['wan1 → internet'], policy_count: 12, policy_enabled_count: 9, policy_disabled_count: 2, policy_status_unknown_count: 1, service_object_count: 8, vip_count: 3, security_profile_count: 6, ipsec_tunnel_count: 2, ssl_vpn_configured: true, ha_configured: false }, fortiguard: { status: 'UNKNOWN', detail: 'fixture' }, findings }), { status: 201 }))
    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('lab')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    expect(await screen.findByLabelText('Synthèse de l’audit')).toHaveTextContent('Total Checks: 5')
    expect(await screen.findByLabelText('Synthèse des statuts')).toHaveTextContent('TOTAL5')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Hostnameparsed-fw')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Modèle100F')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Version FortiOS7.4.3')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Interfaces projetéeswan1, lan1')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Zonesinternet')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Zones SD-WANsdwan-public')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Relations interface → zonewan1 → internet')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Règles firewall12')
    expect(screen.getByLabelText('Inventaire de configuration')).toHaveTextContent('Statut inconnu1')
    expect(screen.getByLabelText('Synthèse des statuts')).toHaveTextContent('N-A1')
    expect(screen.getByLabelText('Synthèse des sévérités')).toHaveTextContent('Critical1')
    expect(screen.getByLabelText('Synthèse par domaine')).toHaveTextContent('Système')
    expect(screen.getByLabelText('Synthèse par domaine')).toHaveTextContent('Wi-Fi')
    const cards = screen.getAllByTestId('finding-card')
    expect(cards.map((card) => card.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('NET-FAIL')]))
    expect(cards[0]).toHaveTextContent('NET-FAIL')
    expect(cards[1]).toHaveTextContent('FW-UNK')
    expect(cards[2]).toHaveTextContent('SYS-PASS')
    expect(cards[3]).toHaveTextContent('WIFI-PASS')
    expect(cards[4]).toHaveTextContent('UTM-NA')
    expect(screen.queryByText('SECRET DETAIL')).not.toBeInTheDocument()
    expect(screen.getByText('Détails V2 de l’audit').closest('details')).not.toHaveAttribute('open')
    await user.click(screen.getByRole('button', { name: 'FAIL' }))
    expect(screen.getAllByTestId('finding-card')).toHaveLength(1)
  })

  it('opens details from the keyboard and expands long object lists on demand', async () => {
    const user = userEvent.setup()
    const objects = Array.from({ length: 5 }, (_, index) => ({ name: `policy-${index + 1}`, object_type: 'policy' }))
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ hostname: 'lab', model: '60E', firmware_version: '7.2.9', interfaces: [], zones: [], sdwan_zones: [] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2', expires_at: '2026-08-12T12:01:00Z', fortiguard: { status: 'UNKNOWN', detail: 'fixture' }, findings: [{ control_id: 'FW-LIST', title: 'Liste', status: 'FAIL', category: 'firewall', severity: 'high', applicability: 'applicable', message: 'fail', evidence: ['preuve legacy', { section: 'system interface', entry: 'wan1', directive: 'allowaccess', tokens: ['ssh'] }], evidence_items: [{ directive: 'allowaccess' }], affected_objects: objects }] }), { status: 201 }))
    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('lab')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
    const details = await screen.findByRole('button', { name: 'Voir les détails' })
    expect(details).toHaveAttribute('aria-expanded', 'false')
    details.focus()
    await user.keyboard('{Enter}')
    expect(details).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('system interface · wan1 · allowaccess · ssh')).toBeInTheDocument()
    expect(screen.getByText('allowaccess')).toBeInTheDocument()
    expect(screen.getByText('preuve legacy')).toBeInTheDocument()
    expect(screen.queryByText('policy · policy-4')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Afficher les 5 éléments' }))
    expect(screen.getByText('policy · policy-5')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Masquer les détails' }))
    expect(screen.queryByText('system interface · wan1 · allowaccess · ssh')).not.toBeInTheDocument()
  })

  it('preserves error, info, unknown domains and long evidence lists', async () => {
    const user = userEvent.setup()
    const evidence = Array.from({ length: 5 }, (_, index) => `preuve-${index + 1}`)
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ hostname: 'lab', model: '60E', firmware_version: '7.2.9', interfaces: [], zones: [], sdwan_zones: [] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2', expires_at: '2026-08-12T12:01:00Z',
        context: { operator_provenance: { source: 'operator-form', operator: 'analyst', method: 'manual-selection' } },
        fortiguard: { status: 'UNKNOWN', detail: 'fixture' },
        findings: [{ control_id: 'CUSTOM-ERROR', title: 'Erreur', status: 'ERROR', category: 'custom', severity: 'info', applicability: 'unknown', message: 'Erreur contrôlée', evidence, affected_objects: [] }],
      }), { status: 201 }))
    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('lab')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
    expect(await screen.findByLabelText('Synthèse des statuts')).toHaveTextContent('ERROR1')
    expect(screen.getByLabelText('Synthèse des sévérités')).toHaveTextContent('Info1')
    expect(screen.getByLabelText('Synthèse par domaine')).toHaveTextContent('Autre')
    expect(screen.queryByText('analyst')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Voir les détails' }))
    expect(screen.getByText('preuve-3')).toBeInTheDocument()
    expect(screen.queryByText('preuve-4')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Afficher les 5 preuves' }))
    expect(screen.getByText('preuve-5')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'ERROR' }))
    expect(screen.getAllByTestId('finding-card')).toHaveLength(1)
  })

  it('ignores a stale preview response after a newer file selection', async () => {
    const user = userEvent.setup()
    let resolveFirst!: (response: Response) => void
    const first = new Promise<Response>((resolve) => { resolveFirst = resolve })
    vi.spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(first)
      .mockResolvedValueOnce(new Response(JSON.stringify({ hostname: 'new-device', model: '70F', firmware_version: '7.4.3', interfaces: [], zones: [], sdwan_zones: [] }), { status: 200 }))
    render(<App />)
    const input = screen.getByLabelText('Configuration FortiGate')
    await user.upload(input, new File(['first'], 'first.conf'))
    await user.upload(input, new File(['second'], 'second.conf'))
    expect(await screen.findByText('new-device')).toBeInTheDocument()
    resolveFirst(new Response(JSON.stringify({ hostname: 'stale-device', model: '60E', firmware_version: '7.2.9', interfaces: [], zones: [], sdwan_zones: [] }), { status: 200 }))
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(screen.queryByText('stale-device')).not.toBeInTheDocument()
    expect(screen.getByText('new-device')).toBeInTheDocument()
  })

  it('unlocks auditing when an obsolete audit finishes after a new preview', async () => {
    const user = userEvent.setup()
    let resolveAudit!: (response: Response) => void
    const pendingAudit = new Promise<Response>((resolve) => { resolveAudit = resolve })
    const oldPreview = { hostname: 'old-device', model: '60E', firmware_version: '7.2.9', interfaces: [], zones: [], sdwan_zones: [] }
    const newPreview = { hostname: 'new-device', model: '70F', firmware_version: '7.4.3', interfaces: [], zones: [], sdwan_zones: [] }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(oldPreview), { status: 200 }))
      .mockReturnValueOnce(pendingAudit)
      .mockResolvedValueOnce(new Response(JSON.stringify(newPreview), { status: 200 }))
    render(<App />)
    const input = screen.getByLabelText('Configuration FortiGate')
    await user.upload(input, new File(['old'], 'old.conf'))
    await screen.findByText('old-device')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
    await user.upload(input, new File(['new'], 'new.conf'))
    await screen.findByText('new-device')
    resolveAudit(new Response(JSON.stringify({ report_id: 'old-report', expires_at: '', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }), { status: 201 }))
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' })).toBeEnabled()
    expect(screen.queryByText('old-report')).not.toBeInTheDocument()
  })

  it('resets equipment context when a different file is selected', async () => {
    const user = userEvent.setup()
    const oldPreview = { hostname: 'old-device', model: '60E', firmware_version: '7.2.9', interfaces: [], zones: [], sdwan_zones: [] }
    const newPreview = { hostname: 'new-device', model: '70F', firmware_version: '7.4.3', interfaces: [], zones: [], sdwan_zones: [] }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(oldPreview), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(newPreview), { status: 200 }))
    render(<App />)
    const input = screen.getByLabelText('Configuration FortiGate')
    await user.upload(input, new File(['old'], 'old.conf'))
    await screen.findByText('old-device')
    await user.type(screen.getByLabelText('Client'), 'Ancien client')
    await user.type(screen.getByLabelText('Site'), 'Ancien site')
    await user.click(screen.getByRole('checkbox', { name: 'HA présent' }))
    await user.click(screen.getByRole('checkbox', { name: 'MPLS / L2L présent' }))
    await user.click(screen.getByRole('checkbox', { name: 'Licence UTM active' }))
    await user.upload(input, new File(['new'], 'new.conf'))
    await screen.findByText('new-device')
    expect(screen.getByLabelText('Client')).toHaveValue('')
    expect(screen.getByLabelText('Site')).toHaveValue('')
    expect(screen.getByRole('checkbox', { name: 'HA présent' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'MPLS / L2L présent' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Licence UTM active' })).not.toBeChecked()
  })

  it('guides the operator through sequential steps without losing context when going back', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      hostname: 'guided-lab', model: '80F', firmware_version: '7.4.3', serial_number: 'FG-guided',
      interfaces: [{ name: 'wan1', role: 'wan' }, { name: 'lan1', role: 'lan' }],
      zones: [{ name: 'internet', interfaces: ['wan1'] }], sdwan_zones: [{ name: 'sdwan-public', interfaces: ['wan1'] }],
    }), { status: 200 }))
    render(<App />)

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['guided'], 'guided.conf'))
    await screen.findByText('guided-lab')
    await user.type(screen.getByLabelText('Client'), 'Client guidé')
    await user.type(screen.getByLabelText('Site'), 'Site guidé')

    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    expect(screen.getByRole('heading', { name: 'Sélection WAN' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Équipement et contexte' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Retour au contexte' }))
    expect(screen.getByLabelText('Client')).toHaveValue('Client guidé')
    expect(screen.getByLabelText('Site')).toHaveValue('Site guidé')

    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    expect(screen.getByRole('heading', { name: 'Options d’audit' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retour à la sélection WAN' }))
    expect(screen.getByRole('heading', { name: 'Sélection WAN' })).toBeInTheDocument()
    expect(screen.getByLabelText('WAN wan1')).toBeChecked()
  })

  it('offers interfaces, zones and SD-WAN choices once and submits only sendable unique names', async () => {
    const user = userEvent.setup()
    const preview = {
      hostname: 'wan-lab', model: '100F', firmware_version: '7.4.3', serial_number: null,
      interfaces: [{ name: 'wan1', role: 'wan' }, { name: '   ', role: 'wan' }],
      zones: [
        { name: 'wan1', interfaces: ['wan1'] },
        { name: 'zone-only', interfaces: ['wan1'] },
        { name: '   ', interfaces: [] },
      ],
      sdwan_zones: [
        { name: 'zone-only', interfaces: ['wan1'] },
        { name: 'sdwan-public', interfaces: ['wan1'] },
      ],
    }
    const report = { report_id: 'wan-report', expires_at: '', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(preview), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(report), { status: 201 }))
    render(<App />)

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['wan'], 'wan.conf'))
    await screen.findByText('wan-lab')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))

    expect(screen.getByRole('group', { name: 'Interfaces WAN' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Zones' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'SD-WAN' })).toBeInTheDocument()
    expect(screen.getAllByRole('checkbox')).toHaveLength(5)
    expect(screen.getByLabelText('WAN wan1')).toBeChecked()
    expect(screen.getByLabelText('WAN zone-only')).not.toBeChecked()
    expect(screen.getByLabelText('WAN sdwan-public')).not.toBeChecked()
    await user.click(screen.getByLabelText('WAN zone-only'))
    await user.click(screen.getByLabelText('WAN sdwan-public'))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const auditCall = vi.mocked(globalThis.fetch).mock.calls[1]
    const body = (auditCall[1] as RequestInit).body as FormData
    expect(body.getAll('selected_wans')).toEqual(['wan1', 'zone-only', 'sdwan-public'])
    expect(await screen.findByRole('heading', { name: 'Synthèse et résultats' })).toBeInTheDocument()
  })

  it('exposes an accessible audit progressbar while the audit request is pending', async () => {
    const user = userEvent.setup()
    let resolveAudit!: (response: Response) => void
    const pendingAudit = new Promise<Response>((resolve) => { resolveAudit = resolve })
    const preview = { hostname: 'progress-lab', model: '60E', firmware_version: '7.4.3', interfaces: [{ name: 'wan1', role: 'wan' }], zones: [], sdwan_zones: [] }
    const report = { report_id: 'progress-report', expires_at: '', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(preview), { status: 200 }))
      .mockReturnValueOnce(pendingAudit)
    render(<App />)

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['progress'], 'progress.conf'))
    await screen.findByText('progress-lab')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const progressbar = screen.getByRole('progressbar', { name: 'Progression de l’audit' })
    expect(progressbar).toHaveAttribute('aria-valuemin', '0')
    expect(progressbar).toHaveAttribute('aria-valuemax', '100')
    expect(progressbar).toHaveAttribute('aria-valuenow', '10')
    expect(screen.getByRole('status')).toHaveTextContent('Audit en cours')

    resolveAudit(new Response(JSON.stringify(report), { status: 201 }))
    expect(await screen.findByRole('heading', { name: 'Synthèse et résultats' })).toBeInTheDocument()
  })

  it('starts a clean new audit from results without retaining the previous report or file', async () => {
    const user = userEvent.setup()
    const preview = { hostname: 'reset-lab', model: '60E', firmware_version: '7.4.3', interfaces: [], zones: [], sdwan_zones: [] }
    const report = { report_id: 'reset-report', expires_at: '', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(preview), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(report), { status: 201 }))
    render(<App />)

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['reset'], 'reset.conf'))
    await screen.findByText('reset-lab')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
    await screen.findByRole('heading', { name: 'Synthèse et résultats' })
    await user.click(screen.getByRole('button', { name: 'Nouvel audit' }))

    expect(screen.getByRole('heading', { name: 'Inspecter une configuration' })).toBeInTheDocument()
    expect(screen.getByText('Aucun fichier sélectionné')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Synthèse et résultats' })).not.toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Parcours d’audit' })).not.toBeInTheDocument()
  })

  it('can resume the inspected file after returning to the upload step', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      hostname: 'resume-lab', model: '60F', firmware_version: '7.4.3', serial_number: null,
      interfaces: [{ name: 'wan1', role: 'wan' }], zones: [], sdwan_zones: [],
    }), { status: 200 }))
    render(<App />)

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['resume'], 'resume.conf'))
    await screen.findByText('resume-lab')
    await user.type(screen.getByLabelText('Client'), 'Client conservé')
    await user.click(screen.getByRole('button', { name: 'Retour à l’upload' }))

    expect(screen.getByRole('heading', { name: 'Inspecter une configuration' })).toBeInTheDocument()
    expect(screen.getByText('resume.conf')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Continuer vers le contexte' }))
    expect(screen.getByRole('heading', { name: 'Équipement et contexte' })).toBeInTheDocument()
    expect(screen.getByLabelText('Client')).toHaveValue('Client conservé')
    expect(globalThis.fetch).toHaveBeenCalledTimes(1)
  })

  it('keeps the guided path sequential without a context shortcut to the audit', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      hostname: 'strict-lab', model: '60F', firmware_version: '7.4.3', serial_number: null,
      interfaces: [{ name: 'wan1', role: 'wan' }], zones: [], sdwan_zones: [],
    }), { status: 200 }))
    render(<App />)

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['strict'], 'strict.conf'))
    await screen.findByText('strict-lab')

    expect(screen.queryByRole('button', { name: 'Lancer l’audit' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Inspecter une configuration' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' })).toBeEnabled()
  })

  it('restores the historical panther header while keeping one h1 and one current step', () => {
    render(<App />)

    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('img', { name: 'Panthère Vysion' })).toHaveAttribute('src', expect.stringContaining('panther'))
    expect(screen.queryByRole('navigation', { name: 'Parcours d’audit' })).not.toBeInTheDocument()
  })
})
