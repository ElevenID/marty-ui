import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@test/utils'

import { ApplicationWizard } from '../applicantVetting/ApplicationWizard'
import { VettingDashboard } from '../applicantVetting/VettingDashboard'

const mockCreateApplication = vi.fn()
const mockGetDocumentTypes = vi.fn()
const mockSubmitApplication = vi.fn()
const mockListApplications = vi.fn()
const mockGetPendingChecks = vi.fn()
const mockGetApplication = vi.fn()
const mockApproveApplication = vi.fn()
const mockRejectApplication = vi.fn()
const mockCompleteCheck = vi.fn()

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => ({
    issuingAuthority: 'Test Authority',
  }),
}))

vi.mock('../../services/applicantApi', () => ({
  createApplication: (...args: unknown[]) => mockCreateApplication(...args),
  getDocumentTypes: (...args: unknown[]) => mockGetDocumentTypes(...args),
  submitApplication: (...args: unknown[]) => mockSubmitApplication(...args),
  listApplications: (...args: unknown[]) => mockListApplications(...args),
  getPendingChecks: (...args: unknown[]) => mockGetPendingChecks(...args),
  getApplication: (...args: unknown[]) => mockGetApplication(...args),
  approveApplication: (...args: unknown[]) => mockApproveApplication(...args),
  rejectApplication: (...args: unknown[]) => mockRejectApplication(...args),
  completeCheck: (...args: unknown[]) => mockCompleteCheck(...args),
}))

describe('ApplicationWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('creates and submits an application through the split adapter flow', async () => {
    mockGetDocumentTypes.mockResolvedValue([
      {
        document_type: 'PASSPORT',
        requirements: [{ check_type: 'IDENTITY_VERIFICATION', required: true }],
      },
    ])
    mockCreateApplication.mockResolvedValue({ id: 'created-1', reference_number: 'REF-1' })
    mockSubmitApplication.mockResolvedValue({ id: 'submitted-1', reference_number: 'REF-1' })
    const onComplete = vi.fn()

    const { user } = render(
      <ApplicationWizard
        applicant={{ id: 'applicant-1', full_name: 'Ada Lovelace' }}
        onComplete={onComplete}
        onCancel={vi.fn()}
      />
    )

    await waitFor(() => {
      expect(screen.getByText('Required Vetting Checks:')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Continue' }))

    await waitFor(() => {
      expect(mockCreateApplication).toHaveBeenCalledWith(expect.objectContaining({
        applicant_id: 'applicant-1',
        document_type: 'PASSPORT',
        issuing_authority: 'Test Authority',
      }))
      expect(screen.getByText('Application Summary')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Submit Application' }))

    await waitFor(() => {
      expect(mockSubmitApplication).toHaveBeenCalledWith('created-1')
      expect(onComplete).toHaveBeenCalledWith({ id: 'submitted-1', reference_number: 'REF-1' })
      expect(screen.getByText('Your application has been submitted successfully!')).toBeInTheDocument()
    })
  })
})

describe('VettingDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('loads applications, shows details, and approves an application', async () => {
    mockListApplications.mockResolvedValue({
      applications: [
        {
          id: 'app-1',
          reference_number: 'REF-1',
          document_type: 'PASSPORT',
          status: 'pending_approval',
          submitted_at: '2026-03-16T12:00:00.000Z',
        },
      ],
    })
    mockGetPendingChecks.mockResolvedValue([{ id: 'check-1' }])
    mockGetApplication.mockResolvedValue({
      application: {
        id: 'app-1',
        reference_number: 'REF-1',
        document_type: 'PASSPORT',
        status: 'pending_approval',
      },
      applicant: { full_name: 'Ada Lovelace' },
      vetting_checks: [
        {
          id: 'check-1',
          check_type: 'IDENTITY_VERIFICATION',
          status: 'pending',
          notes: '',
          is_required: true,
        },
      ],
    })
    mockApproveApplication.mockResolvedValue(undefined)

    const { user } = render(<VettingDashboard />)

    await waitFor(() => {
      expect(screen.getByText('REF-1')).toBeInTheDocument()
      expect(screen.getByText('Pending Review')).toBeInTheDocument()
    })

    await user.click(screen.getByTestId('view-application-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('application-detail-view')).toBeInTheDocument()
      expect(screen.getByText('Ada Lovelace')).toBeInTheDocument()
    })

    await user.click(screen.getByTestId('approve-application-btn'))
    await user.type(screen.getByRole('textbox', { name: 'Notes (optional)' }), 'Looks good')
    await user.click(screen.getByTestId('confirm-approval-btn'))

    await waitFor(() => {
      expect(mockApproveApplication).toHaveBeenCalledWith('app-1', {
        approved_by: 'admin',
        notes: 'Looks good',
      })
      expect(screen.getByText('Application approved successfully')).toBeInTheDocument()
    })
  })
})
