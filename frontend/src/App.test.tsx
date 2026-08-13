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
          findings: [
            {
              control_id: 'NET-WAN-MGMT-001',
              title: 'Administration SSH sur interface WAN',
              status: 'FAIL',
              evidence: ['wan1: allowaccess includes ssh'],
              message: 'SSH est exposé sur une interface WAN.',
              risk: 'Exposition réseau',
              recommendation: 'Retirer SSH.',
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
