import { beforeEach, describe, expect, it, vi } from 'vitest'
import userEvent from '@testing-library/user-event'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import DidIdentitiesPage from './DidIdentitiesPage'

const mockShowNotification = vi.fn()
const mockListSigningKeys = vi.fn()
const mockGetKeyManagementConfig = vi.fn()
const mockListIssuerProfiles = vi.fn()
const mockGetOrganizationLifecycle = vi.fn()
const mockClipboardWriteText = vi.fn()

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key) => key,
  }),
}))

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listSigningKeys: (...args) => mockListSigningKeys(...args),
    getKeyManagementConfig: (...args) => mockGetKeyManagementConfig(...args),
    listIssuerProfiles: (...args) => mockListIssuerProfiles(...args),
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
})