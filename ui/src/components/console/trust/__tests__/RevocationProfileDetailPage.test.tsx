import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, renderWithRouter, screen, waitFor } from '@test/utils'

import RevocationProfileDetailPage from '../RevocationProfileDetailPage'

const getRevocationProfile = vi.fn()
const activateRevocationProfile = vi.fn()

const translations: Record<string, string> = {
  'trust.revocationDetail.checkModeTitle': 'Revocation Check Policy',
  'trust.revocationDetail.mechanismsTitle': 'Revocation Mechanisms',
  'trust.revocationDetail.metadataTitle': 'Profile Metadata',
  'trust.revocationDetail.notFound': 'Revocation profile not found.',
  'trust.revocationDetail.backToList': 'Back to Revocation Profiles',
  'trust.revocationDetail.checkModes.hardFail': 'Hard Fail',
  'trust.revocationDetail.checkModes.softFail': 'Soft Fail',
  'trust.revocationDetail.checkModes.skip': 'Skip',
  'trust.revocationDetail.softFailAdvisory': "Soft-fail mode means verifications will succeed even when the revocation endpoint is unreachable.",
  'trust.revocationDetail.skipAdvisory': 'Revocation checking is disabled for this profile.',
  'trust.breadcrumbs.console': 'Console',
  'trust.breadcrumbs.trust': 'Trust',
  'trust.breadcrumbs.revocationProfiles': 'Revocation Profiles',
  'trust.revocationDetail.profileId': 'Profile ID',
  'trust.revocationDetail.created': 'Created',
  'trust.revocationDetail.updated': 'Last Updated',
  'trust.revocationDetail.disabledAdvisory': 'Credential status checking is disabled for this profile.',
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options: Record<string, unknown> = {}) =>
      String(options.defaultValue || translations[key] || key),
  }),
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  getRevocationProfile: (...args: unknown[]) => getRevocationProfile(...args),
  activateRevocationProfile: (...args: unknown[]) => activateRevocationProfile(...args),
}))

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useParams: () => ({ id: 'rev-profile-1' }),
    useNavigate: () => vi.fn(),
    Link: ({ children, to }: { children: React.ReactNode; to: string }) => (
      <a href={to}>{children}</a>
    ),
  }
})

const PROFILE_FIXTURE = {
  id: 'rev-profile-1',
  name: 'OCSP Check Profile',
  status: 'DRAFT',
  check_mode: 'ALWAYS',
  revocation_mechanism: ['StatusList2021'],
  status_list_url: 'https://example.com/status/1',
  organization_id: 'org-1',
  created_at: '2024-01-15T10:00:00Z',
  updated_at: '2024-06-01T12:00:00Z',
  description: 'Production revocation check configuration.',
}

describe('RevocationProfileDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders profile name and check mode chip after loading', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    const headings = await screen.findAllByText('OCSP Check Profile')
    expect(headings.length).toBeGreaterThan(0)
    expect(getRevocationProfile).toHaveBeenCalledWith('rev-profile-1')
  })

  it('renders check mode panel heading', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    expect(await screen.findByText('Revocation Check Policy')).toBeInTheDocument()
  })

  it('renders mechanisms panel heading', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    expect(await screen.findByText('Revocation Mechanisms')).toBeInTheDocument()
  })

  it('renders status list URL when present', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    expect(await screen.findByText('https://example.com/status/1')).toBeInTheDocument()
  })

  it('renders metadata panel heading', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    expect(await screen.findByText('Profile Metadata')).toBeInTheDocument()
  })

  it('shows an advisory when status checking is disabled', async () => {
    getRevocationProfile.mockResolvedValue({
      ...PROFILE_FIXTURE,
      check_mode: 'DISABLED',
    })

    renderWithRouter(<RevocationProfileDetailPage />)

    expect(
      await screen.findByText(/credential status checking is disabled/i)
    ).toBeInTheDocument()
  })

  it('does not show an advisory for always mode', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    await screen.findAllByText('OCSP Check Profile')

    expect(screen.queryByText(/credential status checking is disabled/i)).not.toBeInTheDocument()
  })

  it('shows error state when profile fetch fails', async () => {
    getRevocationProfile.mockRejectedValue(new Error('Network error'))

    renderWithRouter(<RevocationProfileDetailPage />)

    // Component renders error.message when present
    expect(await screen.findByText('Network error')).toBeInTheDocument()
    expect(screen.getByText('Back to Revocation Profiles')).toBeInTheDocument()
  })

  it('renders breadcrumbs linking to trust sections', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    await screen.findAllByText('OCSP Check Profile')

    expect(screen.getByText('Console')).toBeInTheDocument()
    expect(screen.getByText('Trust')).toBeInTheDocument()
    expect(screen.getByText('Revocation Profiles')).toBeInTheDocument()
  })

  it('renders profile description in metadata section', async () => {
    getRevocationProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<RevocationProfileDetailPage />)

    expect(
      await screen.findByText('Production revocation check configuration.')
    ).toBeInTheDocument()
  })

  it('activates a draft profile and reloads its status', async () => {
    getRevocationProfile
      .mockResolvedValueOnce(PROFILE_FIXTURE)
      .mockResolvedValueOnce({ ...PROFILE_FIXTURE, status: 'ACTIVE' })
    activateRevocationProfile.mockResolvedValue({ ...PROFILE_FIXTURE, status: 'ACTIVE' })

    renderWithRouter(<RevocationProfileDetailPage />)
    fireEvent.click(await screen.findByRole('button', { name: /^activate$/i }))

    await waitFor(() => expect(activateRevocationProfile).toHaveBeenCalledWith('rev-profile-1'))
    expect(await screen.findByText('ACTIVE')).toBeInTheDocument()
  })
})
