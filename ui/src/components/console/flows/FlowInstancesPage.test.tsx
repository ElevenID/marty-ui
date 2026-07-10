import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import userEvent from '@testing-library/user-event'
import FlowInstancesPage from './FlowInstancesPage'

const { mockListFlows, mockListFlowExecutions } = vi.hoisted(() => ({
  mockListFlows: vi.fn(),
  mockListFlowExecutions: vi.fn(),
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
  listFlowExecutions: (...args: unknown[]) => mockListFlowExecutions(...args),
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
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'exec_1',
        status: 'pending',
        currentStep: 1,
        totalSteps: 3,
        startedAt: '2026-04-14T10:00:00Z',
        completedAt: null,
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

    await user.click(screen.getByRole('button', { name: 'flows.refresh' }))

    await waitFor(() => {
      expect(mockListFlows).toHaveBeenCalledTimes(2)
    })
  })

  it('handles malformed API payloads gracefully', async () => {
    mockListFlows.mockResolvedValue({ items: [] })

    renderWithRouter(<FlowInstancesPage />, {
      initialEntries: ['/console/org/operate/flow-instances'],
    })

    await waitFor(() => {
      expect(screen.getByText('No flow instances yet')).toBeInTheDocument()
    })
  })
})
