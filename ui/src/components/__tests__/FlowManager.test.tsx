import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@test/utils'

import FlowManager from '../vendor/FlowManager'

const {
  mockNavigate,
  mockShowSuccess,
  mockShowError,
  mockShowWarning,
  mockListFlows,
  mockListFlowExecutions,
  mockApproveFlowExecution,
  mockListCredentials,
  mockListRevocationBatches,
  mockBatchRevokeCredentials,
  mockSseConnect,
  mockSseDisconnect,
  mockSseOn,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockShowSuccess: vi.fn(),
  mockShowError: vi.fn(),
  mockShowWarning: vi.fn(),
  mockListFlows: vi.fn(),
  mockListFlowExecutions: vi.fn(),
  mockApproveFlowExecution: vi.fn(),
  mockListCredentials: vi.fn(),
  mockListRevocationBatches: vi.fn(),
  mockBatchRevokeCredentials: vi.fn(),
  mockSseConnect: vi.fn(),
  mockSseDisconnect: vi.fn(),
  mockSseOn: vi.fn(() => vi.fn()),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'user-1', organization_id: 'org-1' },
  }),
}))

vi.mock('../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: mockShowSuccess,
    showError: mockShowError,
    showWarning: mockShowWarning,
  }),
}))

vi.mock('../../services/flowsApi', () => ({
  FLOW_STATES: {
    DRAFT: 'draft',
    PUBLISHED: 'published',
    DISABLED: 'disabled',
  },
  default: {
    listFlows: mockListFlows,
    listFlowExecutions: mockListFlowExecutions,
    approveFlowExecution: mockApproveFlowExecution,
  },
}))

vi.mock('../../services/credentialsApi', () => ({
  default: {
    listCredentials: mockListCredentials,
    listRevocationBatches: mockListRevocationBatches,
    batchRevokeCredentials: mockBatchRevokeCredentials,
  },
}))

vi.mock('../../services/sseService', () => ({
  EVENT_TYPES: {
    FLOW_EXECUTION_STARTED: 'flow.execution.started',
    FLOW_EXECUTION_COMPLETED: 'flow.execution.completed',
    APPLICATION_APPROVED: 'application.approved',
    CREDENTIAL_ISSUED: 'credential.issued',
    CREDENTIAL_REVOKED: 'credential.revoked',
    REVOCATION_BATCH_COMPLETED: 'revocation_batch.completed',
  },
  default: {
    connect: mockSseConnect,
    disconnect: mockSseDisconnect,
    on: mockSseOn,
  },
}))

vi.mock('../vendor/FlowPublishDialog', () => ({
  default: () => null,
}))

vi.mock('../vendor/FlowDisableDialog', () => ({
  default: () => null,
}))

vi.mock('../common', () => ({
  EmptyState: ({ title }: { title: string }) => <div>{title}</div>,
}))

describe('FlowManager', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListCredentials.mockResolvedValue([])
    mockListRevocationBatches.mockResolvedValue([])
    mockBatchRevokeCredentials.mockResolvedValue(undefined)
    mockListFlowExecutions.mockResolvedValue([])
  })

  it('falls back to sample flows when the backend is unavailable', async () => {
    mockListFlows.mockRejectedValue(new Error('offline'))

    render(<FlowManager />)

    await waitFor(() => {
      expect(screen.getByText('EU Digital Identity – Employee Issuance')).toBeInTheDocument()
      expect(mockShowWarning).toHaveBeenCalledWith(
        'Backend service unavailable - showing sample data for testing',
        { autoHideDuration: 8000 }
      )
    })

    expect(mockSseConnect).toHaveBeenCalledWith(expect.objectContaining({
      organizationId: 'org-1',
    }))
  })

  it('approves a pending execution from the approval tab', async () => {
    mockListFlows.mockResolvedValue([
      { id: 'flow-1', name: 'Employee Flow', flow_type: 'issuance', status: 'published', approval_strategy: 'manual' },
    ])
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'exec-1',
        flow_id: 'flow-1',
        status: 'pending',
        context: { applicant_id: 'app-1' },
        started_at: '2026-03-16T12:00:00.000Z',
      },
    ])
    mockApproveFlowExecution.mockResolvedValue({})

    const { user } = render(<FlowManager />)

    await waitFor(() => {
      expect(screen.getByText('Employee Flow')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('tab', { name: 'flowManager.tabs.approvals' }))

    await waitFor(() => {
      expect(screen.getByText('flow-1')).toBeInTheDocument()
    })

    const row = screen.getByText('flow-1').closest('tr')
    expect(row).not.toBeNull()
    const buttons = within(row as HTMLElement).getAllByRole('button')
    await user.click(buttons[0])

    await waitFor(() => {
      expect(mockApproveFlowExecution).toHaveBeenCalledWith('flow-1', 'exec-1', {
        approver_id: 'user-1',
        notes: 'Approved via UI',
      })
      expect(mockShowSuccess).toHaveBeenCalledWith('Execution approved', undefined)
    })
  })
})
