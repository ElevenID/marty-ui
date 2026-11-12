import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@test/utils'

import FlowManager from '../vendor/FlowManager'
import { formatOfficialReference } from '../../utils/officialReferences'

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
  mockListTrustProfiles,
  mockListCredentialTemplates,
  mockListDeploymentProfiles,
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
  mockListTrustProfiles: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  mockListDeploymentProfiles: vi.fn(),
  mockSseConnect: vi.fn(),
  mockSseDisconnect: vi.fn(),
  mockSseOn: vi.fn(() => vi.fn()),
}))

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
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

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}))

vi.mock('../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: mockShowSuccess,
    showError: mockShowError,
    showWarning: mockShowWarning,
  }),
}))

vi.mock('../../services/flowsApi', () => ({
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

vi.mock('../../services/presentationPolicyApi', () => ({
  listTrustProfiles: mockListTrustProfiles,
  listCredentialTemplates: mockListCredentialTemplates,
}))

vi.mock('../../services/deploymentProfilesApi', () => ({
  listDeploymentProfiles: mockListDeploymentProfiles,
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
  const initialUrl = window.location.href
  afterEach(() => { window.history.replaceState({}, '', initialUrl) })

  beforeEach(() => {
    vi.clearAllMocks()
    mockListCredentials.mockResolvedValue([])
    mockListRevocationBatches.mockResolvedValue([])
    mockBatchRevokeCredentials.mockResolvedValue(undefined)
    mockListFlowExecutions.mockResolvedValue([])
    mockListTrustProfiles.mockResolvedValue([])
    mockListCredentialTemplates.mockResolvedValue([])
    mockListDeploymentProfiles.mockResolvedValue([])
  })

  it('shows native custom-flow state and references without fabricated publication, wallets or lifecycle actions', async () => {
    mockListFlows.mockResolvedValue([
      { id: 'flow/active?view=one', name: 'Automatic custom flow', flow_type: 'custom', status: 'ACTIVE',
        approval_strategy: 'AUTO', credential_template_id: 'template-1' },
      { id: 'flow-rules', name: 'Rules flow', flow_type: 'custom', status: 'PAUSED', approval_strategy: 'RULES_BASED' },
      { id: 'flow-external', name: 'External flow', flow_type: 'custom', status: 'ARCHIVED', approval_strategy: 'EXTERNAL' },
      { id: 'flow-draft', name: 'Draft flow', flow_type: 'custom', status: 'DRAFT', approval_strategy: 'MANUAL' },
    ])
    const { user } = render(<FlowManager hideHeader />)
    const row = (await screen.findByText('Automatic custom flow')).closest('tr') as HTMLElement
    expect(within(row).getByText('Active').closest('.MuiChip-root')).toHaveClass('MuiChip-colorSuccess')
    expect(within(row).getByText('Auto')).toBeInTheDocument()
    expect(within(row).getByText(formatOfficialReference('template-1', 'template'))).toBeInTheDocument()
    expect(within(row).getByText('No applicant URL available')).toBeInTheDocument()
    expect(screen.getByText('Rules based')).toBeInTheDocument()
    expect(screen.getByText('External')).toBeInTheDocument()
    expect(screen.getByText('Manual')).toBeInTheDocument()
    expect(screen.getAllByText('No credential template linked')).toHaveLength(3)
    expect(screen.queryByText('Not configured')).not.toBeInTheDocument()
    expect(screen.queryByText('Not Published')).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Wallet Targets' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /publish|disable/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Open applicant entry/ })).not.toBeInTheDocument()

    const region = screen.getByRole('region', { name: 'Flow definitions' })
    expect(region).toHaveAttribute('tabindex', '0')
    const details = within(row).getByRole('link', { name: 'View details for Automatic custom flow' })
    expect(details).toHaveAttribute('href', '/console/org/flows/definitions/flow%2Factive%3Fview%3Done')
    region.focus()
    await user.tab()
    expect(details).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(window.location.pathname).toBe('/console/org/flows/definitions/flow%2Factive%3Fview%3Done')
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  it.each([
    { status: 'ACTIVE', public_url: 'https://example.test/apply/flow-1', available: true },
    { status: 'ACTIVE', public_url: 'javascript:alert(1)', available: false },
    { status: 'ACTIVE', public_url: 'https://user:password@example.test/apply', available: false },
    { status: 'ACTIVE', public_url: { href: 'https://example.test/apply' }, available: false },
    { status: 'DRAFT', public_url: 'https://example.test/apply/flow-1', available: false },
  ])('only offers an explicitly supplied usable applicant URL ($status, $public_url)', async ({ status, public_url, available }) => {
    mockListFlows.mockResolvedValue([{ id: 'flow-1', name: 'Provided entry', flow_type: 'custom', status, public_url }])
    render(<FlowManager hideHeader />)
    await screen.findByText('Provided entry')
    const entry = screen.queryByRole('link', { name: 'Open applicant entry for Provided entry' })
    if (available) {
      expect(entry).toHaveAttribute('href', public_url)
      expect(entry).toHaveAttribute('target', '_blank')
      expect(entry).toHaveAttribute('rel', 'noopener noreferrer')
      expect(screen.queryByText('No applicant URL available')).not.toBeInTheDocument()
    } else {
      expect(entry).not.toBeInTheDocument()
      expect(screen.getByText('No applicant URL available')).toBeInTheDocument()
    }
    expect(screen.queryByText('QR')).not.toBeInTheDocument()
  })

  it('surfaces flow loading failures without sample data fallback', async () => {
    mockListFlows.mockRejectedValue(new Error('offline'))

    render(<FlowManager />)

    await waitFor(() => {
      expect(screen.getByText('offline')).toBeInTheDocument()
      expect(screen.queryByText(/EU Digital Identity/i)).not.toBeInTheDocument()
      expect(mockShowError).toHaveBeenCalledWith(
        'Unable to load flow definitions',
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

    const flowReference = formatOfficialReference('flow-1', 'flow')

    await waitFor(() => {
      expect(screen.getByText(flowReference)).toBeInTheDocument()
    })

    const row = screen.getByText(flowReference).closest('tr')
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
