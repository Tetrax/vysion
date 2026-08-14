import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'


describe('Vysion audit tracer', () => {
  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it('uploads one configuration and renders typed findings', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2',
          expires_at: '2026-08-12T12:01:00Z',
          fortiguard: { status: 'AVAILABLE', detail: 'fixture' },
          context: {
            selected_wans: ['wan1'],
            operator_provenance: {
              source: 'operator-form',
              operator: 'analyst@example.invalid',
              captured_at: null,
              method: 'manual-selection',
            },
            client: 'Client synthétique',
            site: 'Paris-lab',
            ha: null,
            mpls: false,
            utm_license: true,
          },
          findings: [
            {
              control_id: 'NET-WAN-MGMT-001',
              title: 'Administration SSH sur interface WAN',
              status: 'FAIL',
              category: 'network',
              priority: 'P0',
              severity: 'high',
              applicability: 'applicable',
              evidence: ['wan1: allowaccess includes ssh'],
              evidence_items: [{
                section: 'system interface',
                entry: 'wan1',
                directive: 'allowaccess',
                tokens: ['ping', 'ssh'],
                line: 3,
                certainty: 'certain',
              }],
              affected_objects: [{ name: 'wan1', object_type: 'interface', reference: null }],
              message: 'SSH est exposé sur une interface WAN.',
              risk: {
                summary: 'Exposition réseau',
                impact: 'Compromission du plan de gestion',
                likelihood: 'high',
                treatment: 'Retirer SSH',
              },
              recommendation: 'Retirer SSH.',
              remediation: 'Modifier allowaccess puis valider.',
              customer_approval: null,
            },
          ],
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<App />)

    const input = screen.getByLabelText('Configuration FortiGate') as HTMLInputElement
    await user.upload(
      input,
      new File(['config system global\nend'], 'synthetic.conf', { type: 'text/plain' }),
    )
    expect(input.files).toHaveLength(1)
    const submit = screen.getByRole('button', { name: 'Lancer l’audit' })
    expect(submit).toBeEnabled()
    await user.click(submit)

    expect(globalThis.fetch).toHaveBeenCalledTimes(1)
    expect(await screen.findByText('Administration SSH sur interface WAN')).toBeInTheDocument()
    expect(screen.getByText('FAIL')).toBeInTheDocument()
    expect(screen.getByText('Client synthétique')).toBeInTheDocument()
    expect(screen.getByText('network', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('P0', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('high', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('applicable', { exact: true })).toBeInTheDocument()
    expect(screen.getByText('system interface · wan1 · allowaccess · ping ssh · ligne 3 · certain'))
      .toBeInTheDocument()
    expect(screen.getByText('interface / wan1')).toBeInTheDocument()
    expect(screen.getByText('Exposition réseau')).toBeInTheDocument()
    expect(screen.getByText('Modifier allowaccess puis valider.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Télécharger le JSON' })).toHaveAttribute(
      'href',
      '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.json',
    )
    expect(screen.getByRole('link', { name: 'Télécharger le DOCX' })).toHaveAttribute(
      'href',
      '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.docx',
    )
    expect(screen.getByRole('link', { name: 'Télécharger le XLSX' })).toHaveAttribute(
      'href',
      '/api/reports/7bd449c4-ef96-4d72-b4f6-2bc099c982a2.xlsx',
    )
  })

  it('renders schema context and enriched finding fields', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          schema_version: 2,
          report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2',
          expires_at: '2026-08-12T12:01:00Z',
          context: {
            selected_wans: ['wan1'],
            client: 'Client synthétique',
            site: 'Paris-lab',
            ha: true,
            mpls: null,
            utm_license: false,
            operator_provenance: { source: 'operator-form', operator: 'analyst' },
          },
          fortiguard: { status: 'AVAILABLE', detail: 'fixture' },
          findings: [{
            control_id: 'NET-WAN-MGMT-001',
            title: 'Administration SSH sur interface WAN',
            status: 'FAIL',
            category: 'network',
            priority: 'P0',
            severity: 'high',
            applicability: 'applicable',
            evidence: ['wan1: allowaccess includes ssh'],
            evidence_items: [{
              section: 'system interface',
              entry: 'wan1',
              directive: 'allowaccess',
              tokens: ['ping', 'ssh'],
              line: 3,
              certainty: 'certain',
            }],
            affected_objects: [{ name: 'wan1', object_type: 'interface' }],
            message: 'SSH est exposé sur une interface WAN.',
            risk: {
              summary: 'Exposition réseau',
              impact: 'Compromission du plan de gestion',
              likelihood: 'élevée',
              treatment: 'Retirer SSH',
            },
            recommendation: 'Retirer SSH.',
            remediation: 'Modifier allowaccess puis vérifier.',
            customer_approval: null,
          }],
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<App />)

    await user.upload(
      screen.getByLabelText('Configuration FortiGate'),
      new File(['config system global\\nend'], 'synthetic.conf', { type: 'text/plain' }),
    )
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    expect(await screen.findByText('Client synthétique')).toBeInTheDocument()
    expect(screen.getByText('Paris-lab')).toBeInTheDocument()
    expect(screen.getByText('Schéma 2')).toBeInTheDocument()
    expect(screen.getByText('network')).toBeInTheDocument()
    expect(screen.getByText('P0')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('applicable')).toBeInTheDocument()
    expect(screen.getByText('Exposition réseau')).toBeInTheDocument()
    expect(screen.getByText('Modifier allowaccess puis vérifier.')).toBeInTheDocument()
  })

  it('shows the FastAPI error detail when an audit is rejected', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({ detail: 'Aucun parseur compatible trouvé' }),
        { status: 422, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<App />)

    await user.upload(
      screen.getByLabelText('Configuration FortiGate'),
      new File(['invalid'], 'unsupported.conf', { type: 'text/plain' }),
    )
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Audit refusé : Aucun parseur compatible trouvé',
    )
  })

  it('removes a previous report when a new audit is rejected', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            report_id: '7bd449c4-ef96-4d72-b4f6-2bc099c982a2',
            expires_at: '2026-08-12T12:01:00Z',
            fortiguard: { status: 'AVAILABLE', detail: 'fixture' },
            findings: [{
              control_id: 'SYS-HOSTNAME-001',
              title: 'Hostname explicite',
              status: 'PASS',
              evidence: ['hostname: safe.example'],
              message: 'Hostname conforme.',
              risk: null,
              recommendation: null,
            }],
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ detail: 'Preuve ambiguë' }),
          { status: 422, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    render(<App />)

    const input = screen.getByLabelText('Configuration FortiGate')
    const submit = screen.getByRole('button', { name: 'Lancer l’audit' })
    await user.upload(input, new File(['valid'], 'valid.conf', { type: 'text/plain' }))
    await user.click(submit)
    expect(await screen.findByText('Hostname explicite')).toBeInTheDocument()

    await user.upload(input, new File(['invalid'], 'invalid.conf', { type: 'text/plain' }))
    await user.click(submit)

    expect(await screen.findByRole('alert')).toHaveTextContent('Audit refusé : Preuve ambiguë')
    expect(screen.queryByText('Hostname explicite')).not.toBeInTheDocument()
  })
})
