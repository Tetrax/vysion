import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const preview = {
  hostname: 'preview-lab.example',
  model: '60E',
  firmware_version: '7.2.9',
  serial_number: 'FG-preview',
  interfaces: [{ name: 'wan1', role: 'wan' }],
  zones: [],
  sdwan_zones: [],
}
const report = {
  report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2',
  fortiguard: { status: 'AVAILABLE', detail: 'fixture' },
  findings: [
    { control_id: 'NET-WAN-MGMT-001', title: 'Administration SSH sur interface WAN', status: 'FAIL' },
    { control_id: 'SYS-HOSTNAME-001', title: 'Hostname conforme', status: 'PASS' },
  ],
}
function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}
async function uploadAndAudit(user: ReturnType<typeof userEvent.setup>) {
  await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['config'], 'synthetic.conf', { type: 'text/plain' }))
  await screen.findByText('preview-lab.example')
  await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
  await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
  await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
}

describe('Vysion workflow V1', () => {
  it('renders the compact V1 results and only the historical downloads', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(preview))
      .mockResolvedValueOnce(jsonResponse(report, 201))
    render(<App />)

    await uploadAndAudit(user)

    expect(await screen.findByText('Administration SSH sur interface WAN')).toBeInTheDocument()
    expect(screen.getByText('Total Checks:')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Download Word Report' })).toHaveAttribute('href', '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.docx')
    expect(screen.getByRole('link', { name: 'Download Excel Report' })).toHaveAttribute('href', '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.xlsx')
    expect(screen.queryByRole('link', { name: 'Download JSON Audit' })).not.toBeInTheDocument()
    for (const removed of ['Détails techniques inspectés', 'Informations complémentaires (optionnelles)', 'Association automatique V2', 'Détails V2 de l’audit', 'Voir les détails', 'Inventaire de configuration']) {
      expect(screen.queryByText(removed)).not.toBeInTheDocument()
    }
  })

  it('submits unchecked V1 context options as explicit negatives', async () => {
    const user = userEvent.setup()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(preview))
      .mockResolvedValueOnce(jsonResponse(report, 201))
    render(<App />)

    await uploadAndAudit(user)

    const body = fetchSpy.mock.calls[1][1]?.body
    expect(body).toBeInstanceOf(FormData)
    const form = body as FormData
    expect(form.get('ha_cabling_redundancy')).toBe('false')
    expect(form.get('ha_context')).toBeNull()
    expect(form.get('mpls_context')).toBe('false')
    expect(form.get('utm_license')).toBe('false')
    expect(form.get('utm_license_status')).toBe('inactive')
  })

  it('shows the API validation message and returns to the options step', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(preview))
      .mockResolvedValueOnce(jsonResponse({ detail: 'Aucun parseur compatible trouvé' }, 422))
    render(<App />)

    await uploadAndAudit(user)

    expect(await screen.findByRole('alert')).toHaveTextContent('Audit refusé : Aucun parseur compatible trouvé')
    expect(screen.getByRole('heading', { name: 'Options d’audit' })).toBeInTheDocument()
  })

  it('clears the previous results when a new file is selected', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(preview))
      .mockResolvedValueOnce(jsonResponse(report, 201))
      .mockResolvedValueOnce(jsonResponse({ ...preview, hostname: 'second-lab' }))
    render(<App />)

    await uploadAndAudit(user)
    expect(await screen.findByText('Administration SSH sur interface WAN')).toBeInTheDocument()

    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['second'], 'second.conf', { type: 'text/plain' }))
    expect(await screen.findByText('second-lab')).toBeInTheDocument()
    expect(screen.queryByText('Administration SSH sur interface WAN')).not.toBeInTheDocument()
  })
})
