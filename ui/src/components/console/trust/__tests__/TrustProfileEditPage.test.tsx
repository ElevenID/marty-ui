import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor, fireEvent, within } from '@test/utils'

import TrustProfileEditPage from '../TrustProfileEditPage'

const getTrustProfile = vi.fn()
const updateTrustProfile = vi.fn()
const mockNavigate = vi.fn()

const translations: Record<string, string> = {
  'trust.trustProfileEdit.title': 'Edit Trust Profile',
  'trust.trustProfileEdit.saveButton': 'Save Changes',
  'trust.trustProfileEdit.saving': 'Saving...',
  'trust.trustProfileEdit.cancel': 'Cancel',
  'trust.trustProfileEdit.notFound': 'Trust profile not found.',
  'trust.trustProfileEdit.backToProfiles': 'Back to Profiles',
  'trust.trustProfileEdit.saveFailed': 'Failed to save trust profile.',
  'trust.trustProfileEdit.statusLabel': 'Status',
  'trust.trustProfileEdit.breadcrumbEdit': 'Edit',
  'trust.breadcrumbs.console': 'Console',
  'trust.breadcrumbs.trust': 'Trust',
  'trust.breadcrumbs.trustProfiles': 'Trust Profiles',
  'wizards.trustProfile.basicsStep.fields.name': 'Profile Name',
  'wizards.trustProfile.basicsStep.fields.description': 'Description',
  'wizards.trustProfile.basicsStep.fields.frameworkType': 'Framework Type',
  'wizards.trustProfile.basicsStep.fields.supportedFormats': 'Supported Credential Formats',
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options: Record<string, unknown> = {}) =>
      String(options.defaultValue || translations[key] || key),
  }),
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  getTrustProfile: (...args: unknown[]) => getTrustProfile(...args),
  updateTrustProfile: (...args: unknown[]) => updateTrustProfile(...args),
}))

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useParams: () => ({ id: 'profile-1' }),
    useNavigate: () => mockNavigate,
    Link: ({ children, to }: { children: React.ReactNode; to: string }) => (
      <a href={to}>{children}</a>
    ),
  }
})

const PROFILE_FIXTURE = {
  id: 'profile-1',
  name: 'Production Trust',
  description: 'Main production profile',
  framework: 'custom',
  profile_type: 'custom',
  supported_formats: ['sd_jwt_vc', 'mdoc'],
  status: 'active',
}

describe('TrustProfileEditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders edit form pre-populated with profile data', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<TrustProfileEditPage />)

    expect(await screen.findByDisplayValue('Production Trust')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Main production profile')).toBeInTheDocument()
  })

  it('renders the Edit Trust Profile heading', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<TrustProfileEditPage />)

    expect(await screen.findByText('Edit Trust Profile')).toBeInTheDocument()
  })

  it('calls getTrustProfile with the id from params', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<TrustProfileEditPage />)

    await waitFor(() => {
      expect(getTrustProfile).toHaveBeenCalledWith('profile-1')
    })
  })

  it('calls updateTrustProfile and navigates on save', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)
    updateTrustProfile.mockResolvedValue({ ...PROFILE_FIXTURE })

    renderWithRouter(<TrustProfileEditPage />)

    const saveButton = await screen.findByTestId('edit.trustProfile.save')
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(updateTrustProfile).toHaveBeenCalledWith(
        'profile-1',
        expect.objectContaining({ name: 'Production Trust' })
      )
    })

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/org/trust/profiles/profile-1')
    })
  })

  it('applies framework presets on edit and unlocks formats again for custom', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)
    updateTrustProfile.mockResolvedValue({ ...PROFILE_FIXTURE })

    renderWithRouter(<TrustProfileEditPage />)

    await screen.findByTestId('edit.trustProfile.frameworkTypeField')
    const jwtFormat = screen.getByTestId('edit.trustProfile.format.jwt_vc')
    const mdocFormat = screen.getByTestId('edit.trustProfile.format.mdoc')
    const ldpFormat = screen.getByTestId('edit.trustProfile.format.ldp_vc')

    fireEvent.mouseDown(within(screen.getByTestId('edit.trustProfile.frameworkTypeField')).getByRole('combobox'))
    fireEvent.click(await screen.findByRole('option', { name: 'ICAO' }))

    await waitFor(() => {
      expect(jwtFormat).not.toBeChecked()
      expect(mdocFormat).toBeChecked()
      expect(ldpFormat).not.toBeChecked()
    })

    expect(jwtFormat).toBeDisabled()
    expect(mdocFormat).toBeDisabled()

    fireEvent.mouseDown(within(screen.getByTestId('edit.trustProfile.frameworkTypeField')).getByRole('combobox'))
    fireEvent.click(await screen.findByRole('option', { name: 'Custom' }))

    await waitFor(() => {
      expect(jwtFormat).not.toBeDisabled()
      expect(ldpFormat).not.toBeDisabled()
    })

    fireEvent.click(jwtFormat)
    fireEvent.click(ldpFormat)
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'))

    await waitFor(() => {
      expect(updateTrustProfile).toHaveBeenCalled()
      const savedPayload = updateTrustProfile.mock.calls.at(-1)?.[1]
      expect(savedPayload.framework_type).toBe('custom')
      expect(savedPayload.supported_formats).toEqual(expect.arrayContaining(['mdoc', 'jwt_vc', 'ldp_vc']))
      expect(savedPayload.supported_formats).not.toContain('sd_jwt_vc')
    })
  })

  it('disables save button when name is empty', async () => {
    getTrustProfile.mockResolvedValue({ ...PROFILE_FIXTURE, name: '' })

    renderWithRouter(<TrustProfileEditPage />)

    const saveButton = await screen.findByTestId('edit.trustProfile.save')
    expect(saveButton).toBeDisabled()
  })

  it('shows error alert when updateTrustProfile rejects', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)
    updateTrustProfile.mockRejectedValue(new Error('Conflict error'))

    renderWithRouter(<TrustProfileEditPage />)

    const saveButton = await screen.findByTestId('edit.trustProfile.save')
    fireEvent.click(saveButton)

    expect(await screen.findByText('Conflict error')).toBeInTheDocument()
  })

  it('shows not-found state when profile fetch rejects', async () => {
    getTrustProfile.mockRejectedValue(new Error('Not found'))

    renderWithRouter(<TrustProfileEditPage />)

    // Component renders error.message when present, falling back to i18n key
    expect(await screen.findByText('Not found')).toBeInTheDocument()
    expect(screen.getByText('Back to Profiles')).toBeInTheDocument()
  })

  it('cancel navigates back to the profile detail page', async () => {
    getTrustProfile.mockResolvedValue(PROFILE_FIXTURE)

    renderWithRouter(<TrustProfileEditPage />)

    await screen.findByText('Edit Trust Profile')
    fireEvent.click(screen.getByText('Cancel'))

    expect(mockNavigate).toHaveBeenCalledWith('/console/org/trust/profiles/profile-1')
  })
})
