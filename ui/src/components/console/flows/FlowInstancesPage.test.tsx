import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import userEvent from '@testing-library/user-event'
import FlowInstancesPage from './FlowInstancesPage'

const { mockGetFlowInstance, mockListFlows, mockListFlowInstances } = vi.hoisted(() => ({
  mockGetFlowInstance: vi.fn(),
  mockListFlows: vi.fn(),
  mockListFlowInstances: vi.fn(),
}))

vi.mock('react-i18next', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-i18next')>()
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => key,
    }),
  }
})

vi.mock('../../../services/flowsApi', () => ({
  listFlows: (...args: unknown[]) => mockListFlows(...args),
  listFlowInstances: (...args: unknown[]) => mockListFlowInstances(...args),
  getFlowInstance: (...args: unknown[]) => mockGetFlowInstance(...args),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}))

describe('FlowInstancesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListFlows.mockResolvedValue([
      { id: 'flow_1', name: 'Issuance Flow' },
    ])
    mockListFlowInstances.mockResolvedValue([
      {
        id: 'exec_1',
        status: 'pending',
        flow_id: 'flow_1',
        current_step: 'issue_credential',
        current_step_index: 1,
        started_at: '2026-04-14T10:00:00Z',
        completed_at: null,
      },
    ])
  })

  it('renders instances and supports refresh without runtime errors', async () => {
    const user = userEvent.setup()
    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances'],
    })

    await waitFor(() => {
      expect(screen.getByText('Issuance Flow')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Refresh' }))

    await waitFor(() => {
      expect(mockListFlows).toHaveBeenCalledTimes(2)
    })
  })

  it('renders a runtime timeline and related-record links on the detail route', async () => {
    mockGetFlowInstance.mockResolvedValue({
      id: 'exec_1',
      flow_id: 'flow_1',
      flow_type: 'physical_document_issuance',
      status: 'pending',
      current_step: 'track_production',
      context_data: {
        application_id: 'application-1',
        physical_document_job: { id: 'job-1', status: 'IN_PRODUCTION' },
      },
      state_history: [{ to_status: 'pending', timestamp: '2026-04-14T10:00:00Z' }],
      started_at: '2026-04-14T10:00:00Z',
    })

    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances/exec_1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Runtime timeline')).toBeInTheDocument()
    })
    expect(screen.getByRole('link', { name: 'application-1' })).toHaveAttribute('href', '/console/org/operate/applications/application-1')
    expect(screen.getByText(/job-1/)).toBeInTheDocument()
  })

  it('handles malformed API payloads gracefully', async () => {
    mockListFlows.mockResolvedValue({ items: [] })
    mockListFlowInstances.mockResolvedValue({ items: [] })

    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances'],
    })

    await waitFor(() => {
      expect(screen.getByText('No flow instances yet')).toBeInTheDocument()
    })
  })
})
