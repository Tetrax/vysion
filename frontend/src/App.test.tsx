import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

afterEach(() => { cleanup(); vi.restoreAllMocks() })
const preview = { hostname: 'preview-lab.example', model: '60E', firmware_version: '7.2.9', serial_number: null, interfaces: [{ name: 'wan1', role: 'wan', address: null, allowaccess: ['ping'] }], zones: [], sdwan_zones: [] }
const finding = {
  control_id: 'NET-WAN-MGMT-001', title: 'Administration SSH sur interface WAN', status: 'FAIL', category: 'network', priority: 'P0', severity: 'high', applicability: 'applicable',
  evidence: ['wan1: allowaccess includes ssh'], evidence_items: [{ section: 'system interface', entry: 'wan1', directive: 'allowaccess', tokens: ['ping', 'ssh'], line: 3, certainty: 'certain' }],
  affected_objects: [{ name: 'wan1', object_type: 'interface' }], message: 'SSH est exposé sur une interface WAN.',
  risk: { summary: 'Exposition réseau', impact: 'Compromission du plan de gestion', likelihood: 'high', treatment: 'Retirer SSH' }, recommendation: 'Retirer SSH.', remediation: 'Modifier allowaccess puis valider.', customer_approval: null,
}
const report = { schema_version: 2, report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2', expires_at: '2026-08-12T12:01:00Z', fortiguard: { status: 'AVAILABLE', detail: 'fixture' }, context: { selected_wans: ['wan1'], operator_provenance: { source: 'operator-form', method: 'manual-selection' }, client: 'Client synthétique', site: 'Paris-lab', ha: null, mpls: false, utm_license: true }, findings: [finding] }
function jsonResponse(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }) }
async function uploadAndAudit(user: ReturnType<typeof userEvent.setup>) {
  await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['config system global\nend'], 'synthetic.conf', { type: 'text/plain' }))
  await screen.findByText('preview-lab.example')
  await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
  await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
  await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
}

describe('Vysion audit tracer', () => {
  it('uploads one configuration and renders compact typed findings with exports', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(preview)).mockResolvedValueOnce(jsonResponse(report, 201))
    render(<App />)
    await uploadAndAudit(user)
    expect((await screen.findAllByText('Administration SSH sur interface WAN')).length).toBeGreaterThan(0)
    expect(screen.getByText('Client synthétique')).toBeInTheDocument()
    expect(screen.queryByText('system interface · wan1 · allowaccess · ping ssh · ligne 3 · certain')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Voir les détails' }))
    expect(screen.getByText('system interface · wan1 · allowaccess · ping ssh · ligne 3 · certain')).toBeInTheDocument()
    expect(screen.getByText('interface · wan1')).toBeInTheDocument()
    expect(screen.getByText('Compromission du plan de gestion')).toBeInTheDocument()
    expect(screen.getByText('Modifier allowaccess puis valider.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Download JSON Audit' })).toHaveAttribute('href', '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.json')
    expect(screen.getByRole('link', { name: 'Download Word Report' })).toHaveAttribute('href', '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.docx')
    expect(screen.getByRole('link', { name: 'Download Excel Report' })).toHaveAttribute('href', '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.xlsx')
  })

  it('renders schema context and enriched finding fields', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(preview)).mockResolvedValueOnce(jsonResponse(report, 201))
    render(<App />)
    await uploadAndAudit(user)
    expect(await screen.findByText('Client synthétique')).toBeInTheDocument()
    expect(screen.getByText('Paris-lab')).toBeInTheDocument()
    expect(screen.getByText(/Schéma 2/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Voir les détails' }))
    expect(screen.getByText('network')).toBeInTheDocument()
    expect(screen.getByText('P0')).toBeInTheDocument()
    expect(screen.getAllByText('high').length).toBeGreaterThan(0)
    expect(screen.getByText('applicable')).toBeInTheDocument()
  })

  it('shows the FastAPI error detail when an audit is rejected', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(preview)).mockResolvedValueOnce(jsonResponse({ detail: 'Aucun parseur compatible trouvé' }, 422))
    render(<App />)
    await uploadAndAudit(user)
    expect(await screen.findByRole('alert')).toHaveTextContent('Audit refusé : Aucun parseur compatible trouvé')
  })

  it('removes a previous report when a new file is selected and its audit is rejected', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(preview)).mockResolvedValueOnce(jsonResponse(report, 201))
      .mockResolvedValueOnce(jsonResponse({ ...preview, hostname: 'second-lab' })).mockResolvedValueOnce(jsonResponse({ detail: 'Preuve ambiguë' }, 422))
    render(<App />)
    await uploadAndAudit(user)
    expect((await screen.findAllByText('Administration SSH sur interface WAN')).length).toBeGreaterThan(0)
    await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['invalid'], 'invalid.conf', { type: 'text/plain' }))
    await screen.findByText('second-lab')
    expect(screen.queryByText('Administration SSH sur interface WAN')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Audit refusé : Preuve ambiguë')
  })
})
