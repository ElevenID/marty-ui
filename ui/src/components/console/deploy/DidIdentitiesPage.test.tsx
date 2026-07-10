import { beforeEach, describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { renderWithRouter, screen, waitFor, within } from '@test/utils'

import DidIdentitiesPage from './DidIdentitiesPage'

const mockShowNotification = vi.fn()
const mockListSigningKeys = vi.fn()
const mockGetKeyManagementConfig = vi.fn()
const mockListIssuerProfiles = vi.fn()
const mockCreateIssuerProfile = vi.fn()
const mockGetOrganizationLifecycle = vi.fn()
const mockClipboardWriteText = vi.fn()

vi.mock('react-i18next', () => ({
  initReactI18next: {
    type: '3rdParty',
    init: vi.fn(),
  },
  useTranslation: () => ({
    t: (key) => key,
  }),
}))

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listSigningKeys: (...args) => mockListSigningKeys(...args),
    getKeyManagementConfig: (...args) => mockGetKeyManagementConfig(...args),
    listIssuerProfiles: (...args) => mockListIssuerProfiles(...args),
    createIssuerProfile: (...args) => mockCreateIssuerProfile(...args),
  },
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org-test-1',
    organizationName: 'Marty Identity Platform',
  }),
}))

vi.mock('../../../services/dashboardApi', () => ({
  getOrganizationLifecycle: (...args) => mockGetOrganizationLifecycle(...args),
}))

describe('DidIdentitiesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    mockListSigningKeys.mockResolvedValue({
      keys: [
        {
          id: 'key-jwk',
          provider_key_name: 'cred-issuer-marty-es256',
          name: 'Marty issuer signing key',
          status: 'active',
          signing_service_id: 'managed-openbao-transit',
          public_jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'abc123',
            y: 'def456',
            kid: 'cred-issuer-marty-es256',
          },
        },
        {
          id: 'key-doc',
          provider_key_name: 'cred-dsc-marty-primary',
          name: 'Marty document signer key',
          status: 'active',
          signing_service_id: 'managed-openbao-transit',
        },
      ],
      domain_config: {
        public_domain: 'beta.elevenidllc.com',
        issuer_base_url: 'https://beta.elevenidllc.com',
      },
    })

    mockGetKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'managed-openbao-transit',
      services: [],
      domain_config: {
        public_domain: 'beta.elevenidllc.com',
        issuer_base_url: 'https://beta.elevenidllc.com',
      },
      service_type_catalog: [],
    })

    mockListIssuerProfiles.mockResolvedValue({
      profiles: [
        {
          id: 'profile-1',
          name: 'did:web identity',
          issuer_did: 'did:web:beta.elevenidllc.com:orgs:marty-identity-platform',
          signing_service_id: 'managed-openbao-transit',
          signing_key_reference: 'cred-issuer-marty-es256',
          status: 'active',
          created_at: '2026-04-18T00:00:00Z',
        },
      ],
    })

    mockCreateIssuerProfile.mockResolvedValue({
      ok: true,
      profile: {
        id: 'profile-imported',
        issuer_did: 'did:web:external.example.com',
        signing_service_id: 'managed-openbao-transit',
        signing_key_reference: 'cred-dsc-marty-primary',
        status: 'active',
      },
    })

    mockGetOrganizationLifecycle.mockResolvedValue({
      planTier: 'community',
    })

    mockClipboardWriteText.mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: mockClipboardWriteText,
      },
      configurable: true,
    })
  })

  it('separates DID method references, artifacts, and issuer profiles into distinct sections', async () => {
    renderWithRouter(<DidIdentitiesPage />, {
      initialEntries: ['/console/org/deploy/issuer-identity'],
    })

    await waitFor(() => {
      expect(screen.getAllByText('did:web:beta.elevenidllc.com').length).toBeGreaterThan(0)
    })

    expect(screen.getByText('DID methods reference')).toBeInTheDocument()
    expect(screen.getByText('Generated DID documents and templates')).toBeInTheDocument()
    expect(screen.getByText('Profiles powering issuance')).toBeInTheDocument()
    expect(screen.getByText('Marty Identity Platform web issuer (Marty ES256)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create DID identity' })).toBeInTheDocument()
  })

  it('shows a DID document preview for a derived did:jwk identity', async () => {
    const user = userEvent.setup()

    renderWithRouter(<DidIdentitiesPage />, {
      initialEntries: ['/console/org/deploy/issuer-identity'],
    })

    await waitFor(() => {
      expect(screen.getAllByText('did:web:beta.elevenidllc.com').length).toBeGreaterThan(0)
    })

    await user.click(screen.getByText(/did:jwk:/))

    expect(screen.getAllByText(/did:jwk:/).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Copy JSON' })).toBeInTheDocument()
  })

  it('imports an existing DID through the selected KMS signing service', async () => {
    const user = userEvent.setup()

    renderWithRouter(<DidIdentitiesPage />, {
      initialEntries: ['/console/org/deploy/issuer-identity'],
    })

    await waitFor(() => {
      expect(screen.getByText('Marty document signer key')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Import DID' }))

    const dialog = screen.getByRole('dialog', { name: 'Import existing DID' })
    await user.type(within(dialog).getByLabelText('DID'), 'did:web:external.example.com')
    await user.click(within(dialog).getByRole('button', { name: 'Import DID' }))

    await waitFor(() => {
      expect(mockCreateIssuerProfile).toHaveBeenCalledWith(expect.objectContaining({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:external.example.com',
        signing_service_id: 'managed-openbao-transit',
        signing_key_reference: 'cred-dsc-marty-primary',
        status: 'active',
      }))
    })
  })
})
