import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@test/utils'

import { ApplicantRegistration } from '../applicantVetting/ApplicantRegistration'
import { ApprovedApplicantSelector } from '../applicantVetting/ApprovedApplicantSelector'

const mockCreateApplicant = vi.fn()
const mockEnrollBiometric = vi.fn()
const mockGetApprovedApplications = vi.fn()

vi.mock('../../services/applicantApi', () => ({
  createApplicant: (...args: unknown[]) => mockCreateApplicant(...args),
  enrollBiometric: (...args: unknown[]) => mockEnrollBiometric(...args),
  getApprovedApplications: (...args: unknown[]) => mockGetApprovedApplications(...args),
}))

vi.mock('../applicantVetting/BiometricCapture', () => ({
  BiometricCapture: ({ onCapture, disabled }: { onCapture?: (payload: unknown) => void; disabled?: boolean }) => (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onCapture?.({ image_data_base64: 'abc123', biometric_type: 'FACIAL' })}
    >
      Mock Capture
    </button>
  ),
}))

describe('Applicant vetting split components', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('completes applicant registration through the split adapter flow', async () => {
    mockCreateApplicant.mockResolvedValue({ id: 'app-1', full_name: 'Ada Lovelace' })
    mockEnrollBiometric.mockResolvedValue(undefined)
    const onComplete = vi.fn()

    const { user } = render(
      <ApplicantRegistration userId="user-1" onComplete={onComplete} onCancel={vi.fn()} />
    )

    await user.type(screen.getByRole('textbox', { name: 'Given Name' }), 'Ada')
    await user.type(screen.getByRole('textbox', { name: 'Family Name' }), 'Lovelace')
    await user.type(screen.getByRole('textbox', { name: 'Email' }), 'ada@example.com')

    await user.click(screen.getByRole('button', { name: 'Continue' }))

    await waitFor(() => {
      expect(mockCreateApplicant).toHaveBeenCalledWith(expect.objectContaining({
        user_id: 'user-1',
        given_name: 'Ada',
        family_name: 'Lovelace',
        email: 'ada@example.com',
      }))
    })

    await user.click(screen.getByRole('button', { name: 'Mock Capture' }))
    await user.click(screen.getByRole('button', { name: 'Complete Registration' }))

    await waitFor(() => {
      expect(mockEnrollBiometric).toHaveBeenCalledWith('app-1', expect.objectContaining({ biometric_type: 'FACIAL' }))
      expect(onComplete).toHaveBeenCalledWith({ id: 'app-1', full_name: 'Ada Lovelace' })
    })
  })

  it('renders approved applicant options from loaded approved applications', async () => {
    mockGetApprovedApplications.mockResolvedValue([
      {
        application_id: 'app-1',
        applicant_name: 'Ada Lovelace',
        reference_number: 'REF-1',
        document_type: 'PASSPORT',
      },
    ])
    const onSelect = vi.fn()
    const { user } = render(<ApprovedApplicantSelector onSelect={onSelect} disabled={false} />)

    await waitFor(() => {
      expect(screen.getByRole('combobox')).toBeInTheDocument()
    })

    fireEvent.mouseDown(screen.getByRole('combobox'))
    const option = await screen.findByText('Ada Lovelace')
    await user.click(option)

    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({
      application_id: 'app-1',
      applicant_name: 'Ada Lovelace',
    }))
  })
})
