import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('Vysion métier v2.2', () => {
  it('keeps the first inspection focused on identity and hides secondary technical details', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      hostname: 'client-fw', model: '100F', firmware_version: '7.4.3', serial_number: 'FG100',
      interfaces: [{ name: 'wan1', role: 'wan', zone: 'internet' }],
      zones: [{ name: 'internet', interfaces: ['wan1'] }], sdwan_zones: [],
    }), { status: 200 }))

    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('client-fw')

    expect(screen.getByText('100F')).toBeInTheDocument()
    expect(screen.getByText('7.4.3')).toBeInTheDocument()
    expect(screen.queryByText('Nombre d’interfaces')).not.toBeInTheDocument()
    expect(screen.getByText('Détails techniques inspectés')).toBeInTheDocument()
  })

  it('sends the enriched equipment context and a typed WAN scope from the same workflow', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({
        hostname: 'client-fw', model: '100F', firmware_version: '7.4.3', serial_number: 'FG100',
        interfaces: [{ name: 'wan1', role: 'wan', zone: 'internet' }],
        zones: [{ name: 'internet', interfaces: ['wan1'] }], sdwan_zones: [],
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        report_id: 'business-report', expires_at: '', context: {},
        fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [],
      }), { status: 201 }))

    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('client-fw')
    await user.type(screen.getByLabelText('Client'), 'Client métier')
    await user.type(screen.getByLabelText('Site'), 'Paris-DC1')
    await user.click(screen.getByText('Informations complémentaires (optionnelles)'))
    fireEvent.change(screen.getByLabelText('Uptime'), { target: { value: '2026-08-18' } })
    await user.type(screen.getByLabelText('Règles sans match'), '7')
    await user.type(screen.getByLabelText('Commentaire contexte'), 'HA à confirmer')
    await user.click(screen.getByRole('checkbox', { name: 'HA présent' }))
    await user.click(screen.getByRole('checkbox', { name: 'Licence UTM active' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const auditCall = vi.mocked(globalThis.fetch).mock.calls[1]
    const body = (auditCall[1] as RequestInit).body as FormData
    expect(body.get('client')).toBe('Client métier')
    expect(body.get('site')).toBe('Paris-DC1')
    expect(body.get('serial_number')).toBe('FG100')
    expect(body.get('uptime')).toBe('2026-08-18')
    expect(body.get('unmatched_rules')).toBe('7')
    expect(body.get('context_comment')).toBe('HA à confirmer')
    expect(body.has('operator')).toBe(false)
    expect(body.get('ha_context')).toBe('true')
    expect(body.has('mpls_context')).toBe(false)
    expect(body.get('utm_license_status')).toBe('active')
    expect(body.has('utm_license_expiration')).toBe(false)
    expect(body.has('utm_license_provenance')).toBe(false)
    expect(body.get('selected_wan_scopes')).toBe(JSON.stringify([{ name: 'wan1', kind: 'interface' }]))
  })

  it('lets the operator choose a zone relation for a name shared by an interface and a zone', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      hostname: 'shared-name', model: '60E', firmware_version: '7.4.3', serial_number: null,
      interfaces: [{ name: 'internet', role: 'wan', zone: 'internet' }],
      zones: [{ name: 'internet', interfaces: ['internet'] }], sdwan_zones: [],
    }), { status: 200 }))

    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('shared-name')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))

    expect(screen.getByLabelText('Type WAN internet')).toBeInTheDocument()
    await user.selectOptions(screen.getByLabelText('Type WAN internet'), 'zone')
    expect(screen.getByLabelText('Type WAN internet')).toHaveValue('zone')
  })
})
