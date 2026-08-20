import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

const preview = {
  hostname: 'guided-lab', model: '80F', firmware_version: '7.4.3', serial_number: 'FG-guided',
  interfaces: [{ name: 'wan1', role: 'wan' }, { name: 'lan1', role: 'lan' }],
  zones: [{ name: 'internet', interfaces: ['wan1'] }], sdwan_zones: [{ name: 'sdwan-public', interfaces: ['wan1'] }],
}
const report = { report_id: 'guided-report', fortiguard: { status: 'UNKNOWN', detail: '' }, findings: [] }

async function upload(user: ReturnType<typeof userEvent.setup>, value = preview) {
  await user.upload(screen.getByLabelText('Configuration FortiGate'), new File(['guided'], 'guided.conf'))
  await screen.findByText(value.hostname)
}

describe('Vysion guided V1 workflow', () => {
  it('keeps the sequential path and preserves context across visible back buttons', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(preview))
    render(<App />)

    await upload(user)
    await user.type(screen.getByLabelText('Client'), 'Client guidé')
    await user.type(screen.getByLabelText('Site'), 'Site guidé')
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    expect(screen.getByRole('heading', { name: 'Sélection WAN' })).toBeInTheDocument()
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

  it('shows every SD-WAN member and the zone-to-members relation', async () => {
    const user = userEvent.setup()
    const sdwanPreview = {
      ...preview,
      sdwan_zones: [
        { name: 'Z-INTERNET', interfaces: ['wan1', 'wan2'], proof_state: 'proven' },
        { name: 'Z-EMPTY', interfaces: [], proof_state: 'unknown' },
      ],
      sdwan_members: [
        { name: 'wan1', zones: ['Z-INTERNET'] },
        { name: 'wan2', zones: ['Z-INTERNET'] },
      ],
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(sdwanPreview))
    render(<App />)

    await upload(user, sdwanPreview)
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))

    expect(screen.getByRole('group', { name: 'Membres physiques SD-WAN' })).toBeInTheDocument()
    expect(screen.getByLabelText('WAN membre SD-WAN wan1')).toBeChecked()
    expect(screen.getByLabelText('WAN membre SD-WAN wan2')).toBeChecked()
    expect(screen.getByText(/SD-WAN Zone: Z-INTERNET → wan1, wan2/)).toBeInTheDocument()
    expect(screen.getByText(/SD-WAN Zone: Z-EMPTY → Aucun membre observé/)).toBeInTheDocument()
  })

  it('exposes audit progress while the request is pending', async () => {
    const user = userEvent.setup()
    let resolveAudit!: (response: Response) => void
    const pendingAudit = new Promise<Response>((resolve) => { resolveAudit = resolve })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(preview)).mockReturnValueOnce(pendingAudit)
    render(<App />)

    await upload(user)
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))

    const progressbar = screen.getByRole('progressbar', { name: 'Progression de l’audit' })
    expect(progressbar).toHaveAttribute('aria-valuemin', '0')
    expect(progressbar).toHaveAttribute('aria-valuemax', '100')
    expect(progressbar).toHaveAttribute('aria-valuenow', '10')
    expect(screen.getByRole('status')).toHaveTextContent('Audit en cours')

    resolveAudit(jsonResponse(report, 201))
    expect(await screen.findByRole('heading', { name: 'Synthèse et résultats' })).toBeInTheDocument()
  })

  it('ignores a stale preview after a newer file selection', async () => {
    const user = userEvent.setup()
    let resolveFirst!: (response: Response) => void
    const first = new Promise<Response>((resolve) => { resolveFirst = resolve })
    vi.spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(first)
      .mockResolvedValueOnce(jsonResponse({ ...preview, hostname: 'new-device' }))
    render(<App />)
    const input = screen.getByLabelText('Configuration FortiGate')

    await user.upload(input, new File(['first'], 'first.conf'))
    await user.upload(input, new File(['second'], 'second.conf'))
    expect(await screen.findByText('new-device')).toBeInTheDocument()
    resolveFirst(jsonResponse({ ...preview, hostname: 'stale-device' }))
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(screen.queryByText('stale-device')).not.toBeInTheDocument()
  })

  it('starts a clean new audit from the historical results screen', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse(preview)).mockResolvedValueOnce(jsonResponse(report, 201))
    render(<App />)

    await upload(user)
    await user.click(screen.getByRole('button', { name: 'Continuer vers la sélection WAN' }))
    await user.click(screen.getByRole('button', { name: 'Continuer vers les options d’audit' }))
    await user.click(screen.getByRole('button', { name: 'Lancer l’audit' }))
    await screen.findByRole('heading', { name: 'Synthèse et résultats' })
    await user.click(screen.getByRole('button', { name: 'Nouvel audit' }))

    expect(screen.getByRole('heading', { name: 'Inspecter une configuration' })).toBeInTheDocument()
    expect(screen.getByText('Aucun fichier sélectionné')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Synthèse et résultats' })).not.toBeInTheDocument()
  })
})
