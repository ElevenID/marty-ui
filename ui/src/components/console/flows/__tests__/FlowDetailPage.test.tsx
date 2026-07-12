import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import FlowDetailPage from '../FlowDetailPage'

const { mockGetFlow, mockNavigate } = vi.hoisted(() => ({
  mockGetFlow: vi.fn(),
  mockNavigate: vi.fn(),
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
        }
        return translations[key] || key
      },
    }),
  }
})

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useParams: () => ({ flowId: 'flow-1' }),
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../../../services/flowsApi', () => ({
  getFlow: (...args: unknown[]) => mockGetFlow(...args),
  publishFlow: vi.fn(),
  testFlow: vi.fn(),
  validateFlow: vi.fn(),
}))

describe('FlowDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetFlow.mockResolvedValue({
      id: 'flow-1',
      name: 'Production credential flow',
      status: 'ACTIVE',
      flow_type: 'oid4vci_pre_authorized',
      resolved_steps: ['create_offer', 'token_exchange', 'credential_request', 'issue_credential'],
      environment: 'production',
      public_url: 'https://beta.elevenidllc.com/apply/flow-1',
      created_at: '2026-07-09T12:00:00Z',
      updated_at: '2026-07-09T12:00:00Z',
    })
  })

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
    renderWithRouter(<FlowDetailPage />, {
      initialEntries: ['/console/org/flows/definitions/flow-1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Production credential flow')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Download QR' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Download QR Code' })).toBeDisabled()
  })
})
