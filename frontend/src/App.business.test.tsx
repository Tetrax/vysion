import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('Vysion V1 business path', () => {
  it('submits the historical context fields and keeps removed context fields out of the request', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response({
        hostname: 'client-fw', model: '100F', firmware_version: '7.4.3', serial_number: 'FG100',
        interfaces: [{ name: 'wan1', role: 'wan' }], zones: [{ name: 'internet', interfaces: ['wan1'] }], sdwan_zones: [],
      }))
      .mockResolvedValueOnce(response({ report_id: 'business-report', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }, 201))

    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('client-fw')
    await user.type(screen.getByLabelText('Client'), 'Client métier')
    await user.type(screen.getByLabelText('Site'), 'Paris-DC1')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.type(screen.getByLabelText('Règles sans match options'), '{selectall}7')
    await user.click(screen.getByRole('checkbox', { name: 'HA présent' }))
    await user.click(screen.getByRole('checkbox', { name: 'Licence UTM active' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const auditCall = vi.mocked(globalThis.fetch).mock.calls[1]
    const body = (auditCall[1] as RequestInit).body as FormData
    expect(body.get('client')).toBe('Client métier')
    expect(body.get('site')).toBe('Paris-DC1')
    expect(body.get('serial_number')).toBe('FG100')
    expect(body.get('unmatched_rules')).toBe('7')
    expect(body.get('ha_cabling_redundancy')).toBe('true')
    expect(body.get('ha_context')).toBeNull()
    expect(body.get('utm_license_status')).toBe('active')
    expect(body.has('context_comment')).toBe(false)
    expect(body.has('comment')).toBe(false)
    expect(body.has('automatic_wan')).toBe(false)
    expect(body.get('selected_wan_scopes')).toBe(JSON.stringify([{ name: 'wan1', kind: 'interface' }]))
  })

  it('keeps interface and zone selections distinct when names collide', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response({
        hostname: 'shared-name', model: '60E', firmware_version: '7.4.3', serial_number: null,
        interfaces: [{ name: 'internet', role: 'wan' }], zones: [{ name: 'internet', interfaces: ['internet'] }], sdwan_zones: [],
      }))
      .mockResolvedValueOnce(response({ report_id: 'collision-report', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }, 201))

    render(<App />)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['safe'], 'safe.conf'))
    await screen.findByText('shared-name')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByLabelText('WAN zone internet'))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const auditCall = vi.mocked(globalThis.fetch).mock.calls[1]
    const body = (auditCall[1] as RequestInit).body as FormData
    expect(JSON.parse(body.get('selected_wan_scopes') as string)).toEqual([
      { name: 'internet', kind: 'interface' },
      { name: 'internet', kind: 'zone' },
    ])
    expect(body.getAll('selected_wans')).toEqual([])
    expect(screen.queryByText('Association automatique V2')).not.toBeInTheDocument()
  })
})
