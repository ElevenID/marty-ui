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

  it('shows Canvas course source context in application details', async () => {
    mockGetMyApplications.mockResolvedValue({
      applications: [
        {
          id: 'app-canvas-1',
          credential_display_name: 'Interoperable Credentials Foundations Badge',
          credential_configuration_id: 'cfg-canvas-badge',
          status: 'SUBMITTED',
          submitted_at: '2026-05-18T00:00:00.000Z',
          updated_at: '2026-05-18T00:05:00.000Z',
          integration_context: {
            delivery_mode: 'wallet_plus_canvas_mirror',
            canvas: {
              canvas_course_name: 'ElevenID LTI Test Course',
              canvas_assignment_name: 'Interoperable Credentials Quiz',
              canvas_account_id: 'canvas-real-account-1',
              canvas_program_binding_id: 'binding-1',
            },
          },
        },
      ],
    })

    const { user } = render(<MyIdentityPage />)

    await screen.findByText('Interoperable Credentials Foundations Badge')
    await user.click(screen.getByRole('button', { name: 'Details' }))

    expect(await screen.findByTestId('identity-canvas-source')).toBeInTheDocument()
    expect(screen.getByText('ElevenID LTI Test Course')).toBeInTheDocument()
    expect(screen.getByText('Interoperable Credentials Quiz')).toBeInTheDocument()
    expect(screen.getByText('canvas-real-account-1')).toBeInTheDocument()
    expect(screen.getByText('Delivery: wallet plus canvas mirror')).toBeInTheDocument()
  })

  it('shows Canvas Credentials mirror delivery in credential details', async () => {
    mockGetMyApplications.mockResolvedValue({ applications: [] })
    mockGetMyCredentials.mockResolvedValue({
      credentials: [
        {
          id: 'cred-1',
          credential_display_name: 'Interoperable Credentials Foundations Badge',
          credential_template_id: 'cfg-canvas-badge',
          issuer_did: 'did:web:beta.elevenidllc.com:orgs:marty',
          badge_image_url: 'https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge/image.svg',
          status: 'ACTIVE',
          issued_at: '2026-05-18T00:00:00.000Z',
          updated_at: '2026-05-18T00:05:00.000Z',
          deliveries: [
            {
              id: 'delivery-1',
              delivery_target: 'canvas_credentials',
              status: 'delivered',
              external_credential_id: 'canvas-cred-1',
            },
          ],
        },
      ],
    })

    const { user } = render(<MyIdentityPage />)

    await screen.findByText('Interoperable Credentials Foundations Badge')
    expect(screen.getByRole('img', { name: /interoperable credentials foundations badge/i })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /view interoperable credentials foundations badge details/i }))

    expect(await screen.findByText('Credential Details')).toBeInTheDocument()
    expect(screen.getByText('did:web:beta.elevenidllc.com:orgs:marty')).toBeInTheDocument()
    expect(screen.getAllByRole('img', { name: /interoperable credentials foundations badge/i }).length).toBeGreaterThan(0)
    expect(screen.getByText('Claim: Claimed')).toBeInTheDocument()
    expect(screen.getByTestId('identity-canvas-delivery')).toBeInTheDocument()
    expect(screen.getByText('Canvas Credentials display')).toBeInTheDocument()
    expect(screen.getByText('Delivered')).toBeInTheDocument()
    expect(screen.getByText(/canvas-cred-1/)).toBeInTheDocument()
  })
})
