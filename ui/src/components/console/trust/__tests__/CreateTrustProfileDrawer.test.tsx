import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@test/utils'
import { renderWithRouter } from '@test/utils'

import CreateTrustProfileDrawer from '../CreateTrustProfileDrawer'

const showNotification = vi.fn()
const createTrustProfile = vi.fn()
const addTrustProfileIssuer = vi.fn()

const translations: Record<string, string> = {
  'trust.createTrustProfileDrawer.title': 'Create Trust Profile',
  'trust.createTrustProfileDrawer.profileName': 'Profile Name',
  'trust.createTrustProfileDrawer.profileNamePlaceholder': 'Production Trust Profile',
  'trust.createTrustProfileDrawer.profileNameHelper': 'Enter a descriptive profile name.',
  'trust.createTrustProfileDrawer.description': 'Description',
  'trust.createTrustProfileDrawer.descriptionPlaceholder': 'Describe how this profile is used.',
  'trust.createTrustProfileDrawer.descriptionHelper': 'Optional description.',
  'trust.createTrustProfileDrawer.issuerDid': 'Trusted issuer DID',
  'trust.createTrustProfileDrawer.issuerDidPlaceholder': 'did:web:issuer.example.com',
  'trust.createTrustProfileDrawer.issuerDidHelper': 'Provide one issuer DID to create a protocol-valid trust profile.',
  'trust.createTrustProfileDrawer.successMessage': 'Created {{name}}',
  'trust.failedToLoad': 'Organization context is required to create a trust profile.',
  'resourceDrawer.quickCreateInfo': 'Quick create mode.',
  'resourceDrawer.advancedConfigPrefix': 'For advanced setup,',
  'resourceDrawer.openFullEditor': 'Open Full Editor',
  'resourceDrawer.create': 'Create',
  'resourceDrawer.creating': 'Creating...',
  'resourceDrawer.failedToCreate': 'Failed to create resource.',
  'actions.cancel': 'Cancel',
}

let authState = { organizationId: 'org-1' }

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options: Record<string, unknown> = {}) => {
      const template = translations[key] || String(options.defaultValue || key)
      return template.replace(/\{\{(.*?)\}\}/g, (_, token) => String(options[token.trim()] ?? ''))
    },
  }),
}))

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => authState,
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: authState.organizationId }),
}))

vi.mock('../../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification,
  }),
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  createTrustProfile: (...args: unknown[]) => createTrustProfile(...args),
  addTrustProfileIssuer: (...args: unknown[]) => addTrustProfileIssuer(...args),
}))

describe('CreateTrustProfileDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authState = { organizationId: 'org-1' }
    createTrustProfile.mockResolvedValue({ id: 'trust-profile-1' })
    addTrustProfileIssuer.mockResolvedValue({ id: 'issuer-link-1' })
  })

  it('submits canonical trust profile and issuer link payloads', async () => {
    const onClose = vi.fn()
    const onSuccess = vi.fn()
    const { user } = renderWithRouter(
      <CreateTrustProfileDrawer open onClose={onClose} onSuccess={onSuccess} />
    )

    await user.type(screen.getByPlaceholderText('Production Trust Profile'), 'Production Trust')
    await user.type(screen.getByPlaceholderText('Describe how this profile is used.'), 'Primary production issuer policy')
    await user.type(screen.getByPlaceholderText('did:web:issuer.example.com'), 'did:web:issuer.example.com')

    await user.click(screen.getByRole('button', { name: 'Create' }))

    await waitFor(() => {
      expect(createTrustProfile).toHaveBeenCalledWith({
        organization_id: 'org-1',
        name: 'Production Trust',
        description: 'Primary production issuer policy',
        supported_formats: ['sd_jwt_vc', 'mdoc'],
        trusted_issuers: [
          {
            did: 'did:web:issuer.example.com',
            name: 'did:web:issuer.example.com',
          },
        ],
      })
    })

    expect(addTrustProfileIssuer).toHaveBeenCalledWith('trust-profile-1', {
      name: 'did:web:issuer.example.com',
      issuer_did: 'did:web:issuer.example.com',
    })
    expect(showNotification).toHaveBeenCalledWith({
      message: 'Created Production Trust',
      severity: 'success',
    })
    expect(onSuccess).toHaveBeenCalledWith({ id: 'trust-profile-1' })
    expect(onClose).toHaveBeenCalled()
  })

  it('links advanced editor to the routed trust profile wizard path', () => {
    renderWithRouter(<CreateTrustProfileDrawer open onClose={vi.fn()} onSuccess={vi.fn()} />)

    expect(screen.getByRole('link', { name: /Open Full Editor/i })).toHaveAttribute(
      'href',
      '/console/org/trust/profiles/new'
    )
  })
})
