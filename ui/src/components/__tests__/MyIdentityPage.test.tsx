import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@test/utils'

import MyIdentityPage from '../console/applicant/MyIdentityPage'

const {
  mockGetMyCredentials,
  mockGetMyApplications,
} = vi.hoisted(() => ({
  mockGetMyCredentials: vi.fn(),
  mockGetMyApplications: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (_key: string, defaultValue?: string) => defaultValue || _key }),
}))

vi.mock('../../services/applicantApi', () => ({
  getMyCredentials: mockGetMyCredentials,
  getMyApplications: mockGetMyApplications,
}))

vi.mock('../console/applicant/ClaimCredentialDialog', () => ({
  default: ({ open, applicationId }: { open: boolean; applicationId?: string | null }) => (
    open ? <div data-testid="claim-credential-dialog">{applicationId}</div> : null
  ),
}))

describe('MyIdentityPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetMyCredentials.mockResolvedValue({ credentials: [] })
    mockGetMyApplications.mockResolvedValue({
      applications: [
        {
          id: 'app-1',
          credential_display_name: 'Verified Member Badge',
          credential_configuration_id: 'cfg-login-badge',
          status: 'CREDENTIALED',
          submitted_at: '2026-05-18T00:00:00.000Z',
          updated_at: '2026-05-18T00:05:00.000Z',
        },
      ],
    })
  })

  it('allows applicants to receive the login badge again from the identity dashboard', async () => {
    const { user } = render(
      <MyIdentityPage />,
    )

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Receive Again' })).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Receive Again' }))

    expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('app-1')
  })
})
