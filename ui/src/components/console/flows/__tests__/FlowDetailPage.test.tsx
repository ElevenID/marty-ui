import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, renderWithRouter, screen, waitFor } from '@test/utils'
import FlowDetailPage from '../FlowDetailPage'
import * as publicEntry from '../../../../application/routing/publicEntry'

const { mockGetFlow, mockNavigate, route } = vi.hoisted(() => ({
  mockGetFlow: vi.fn(),
  mockNavigate: vi.fn(),
  route: { flowId: 'flow-1' },
}))

vi.mock('react-i18next', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-i18next')>()
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => {
        const translations: Record<string, string> = {
          'flows.flowDetail.runtime.notAvailable': 'N/A',
          'flows.flowDetail.configuration.notAvailable': 'N/A',
          'flows.flowDetail.entryPoints.downloadQrButton': 'Download QR Code',
          'flows.flowDetail.actions.downloadQr': 'Download QR',
          'flows.flowDetail.actions.previewButton': 'Preview applicant experience',
        }
        return translations[key] || key
      },
    }),
  }
})

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
  return {
    ...actual,
    useParams: () => route,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../../../services/flowsApi', () => ({
  getFlow: (...args: unknown[]) => mockGetFlow(...args),
  publishFlow: vi.fn(),
  testFlow: vi.fn(),
  validateFlow: vi.fn(),
}))

const nativeFlow = {
  id: 'flow-1',
  organization_id: 'owner-org',
  name: 'Production credential flow',
  status: 'ACTIVE',
  flow_type: 'oid4vci_pre_authorized',
  resolved_steps: ['create_offer', 'token_exchange', 'credential_request', 'issue_credential'],
  created_at: '2026-07-09T12:00:00Z',
  updated_at: '2026-07-09T12:00:00Z',
}

describe('FlowDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.flowId = 'flow-1'
    mockGetFlow.mockResolvedValue(nativeFlow)
  })

  afterEach(() => { vi.restoreAllMocks() })

  it('does not invent runtime metrics when the API omits stats', async () => {
    renderWithRouter(<FlowDetailPage />, {
      initialEntries: ['/console/org/flows/definitions/flow-1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Production credential flow')).toBeInTheDocument()
    })

    expect(screen.queryByText('142')).not.toBeInTheDocument()
    expect(screen.queryByText('12')).not.toBeInTheDocument()
    expect(screen.queryByText('130')).not.toBeInTheDocument()
    expect(screen.queryByText('EU Digital Identity Credential')).not.toBeInTheDocument()
    expect(screen.queryByText('Employee email required (domain: example.com)')).not.toBeInTheDocument()
    expect(screen.queryByText('Open Badge 2.0, EUDI-ready')).not.toBeInTheDocument()
    expect(screen.getAllByText('N/A').length).toBeGreaterThanOrEqual(8)
  })

  it('keeps QR download disabled until a real QR payload exists', async () => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, public_url: 'https://example.test/apply/flow-1' })
    renderWithRouter(<FlowDetailPage />, {
      initialEntries: ['/console/org/flows/definitions/flow-1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Production credential flow')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Download QR' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Download QR Code' })).toBeDisabled()
  })

  it.each(['DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED'])('opens the native %s definition in its owned preview without a public URL', async status => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, status })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const { user } = renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    await user.click(screen.getByRole('button', { name: 'Preview applicant experience' }))

    expect(open).toHaveBeenCalledExactlyOnceWith('/applicant/preview/flows/flow-1?organization_id=owner-org', '_blank', 'noopener,noreferrer')
  })

  it.each([{ id: 'different-flow' }, { organization_id: undefined }, { organization_id: '' }, { organization_id: 42 }])('does not open a preview with an invalid native identity: %j', async replacement => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, ...replacement })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    const button = screen.getByRole('button', { name: 'Preview applicant experience' })
    expect(button).toBeDisabled()
    fireEvent.click(button)
    expect(open).not.toHaveBeenCalled()
  })

  it('encodes the definition and owner and respects public-entry navigation', async () => {
    route.flowId = 'flow/one?two'
    mockGetFlow.mockResolvedValue({ ...nativeFlow, id: route.flowId, organization_id: 'org/name&part' })
    const href = vi.spyOn(publicEntry, 'publicEntryHref').mockImplementation(destination => `https://canonical.example${destination}`)
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const { user } = renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    await user.click(screen.getByRole('button', { name: 'Preview applicant experience' }))

    const path = '/applicant/preview/flows/flow%2Fone%3Ftwo?organization_id=org%2Fname%26part'
    expect(href).toHaveBeenCalledWith(path)
    expect(open).toHaveBeenCalledExactlyOnceWith(`https://canonical.example${path}`, '_blank', 'noopener,noreferrer')
  })
})
