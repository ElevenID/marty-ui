import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import IssuerIdentityWizard from './IssuerIdentityWizard'

const {
  mockListSigningKeys,
  mockGetKeyManagementConfig,
  mockCreateSigningKey,
  mockCreateIssuerProfile,
  mockPublishServiceToJwks,
  mockPublishServiceToDidVm,
  mockShowNotification,
  mockGetOrganizationLifecycle,
} = vi.hoisted(() => ({
  mockListSigningKeys: vi.fn(),
  mockGetKeyManagementConfig: vi.fn(),
  mockCreateSigningKey: vi.fn(),
  mockCreateIssuerProfile: vi.fn(),
  mockPublishServiceToJwks: vi.fn(),
  mockPublishServiceToDidVm: vi.fn(),
  mockShowNotification: vi.fn(),
  mockGetOrganizationLifecycle: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}))

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listSigningKeys: (...args: unknown[]) => mockListSigningKeys(...args),
    getKeyManagementConfig: (...args: unknown[]) => mockGetKeyManagementConfig(...args),
    createSigningKey: (...args: unknown[]) => mockCreateSigningKey(...args),
    createIssuerProfile: (...args: unknown[]) => mockCreateIssuerProfile(...args),
    publishServiceToJwks: (...args: unknown[]) => mockPublishServiceToJwks(...args),
    publishServiceToDidVm: (...args: unknown[]) => mockPublishServiceToDidVm(...args),
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
    organizationName: 'Test Org',
  }),
}))

vi.mock('../../../services/dashboardApi', () => ({
  getOrganizationLifecycle: (...args: unknown[]) => mockGetOrganizationLifecycle(...args),
}))

const EC_JWK = { kty: 'EC', crv: 'P-256', x: 'abc123', y: 'def456', kid: 'cred-issuer-test-es256' }

const SIGNING_KEYS_WITH_JWK = {
  keys: [
    {
      id: 'key-1',
      provider_key_name: 'cred-issuer-test-es256',
      name: 'Test issuer key',
      status: 'active',
      public_jwk: EC_JWK,
    },
  ],
  domain_config: {
    public_domain: 'beta.example.com',
    issuer_base_url: 'https://beta.example.com',
  },
}

const KEY_MANAGEMENT_CONFIG_WITH_SERVICE = {
  supports_native_key_management: false,
  default_service_id: 'managed-openbao-transit',
  services: [
    {
      id: 'managed-openbao-transit',
      name: 'Marty managed OpenBao transit',
      service_type: 'openbao-transit',
      provider: 'openbao',
      status: 'configured',
      managed: true,
    },
  ],
  domain_config: {
    public_domain: 'beta.example.com',
    issuer_base_url: 'https://beta.example.com',
  },
  service_type_catalog: [],
}

describe('IssuerIdentityWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListSigningKeys.mockResolvedValue(SIGNING_KEYS_WITH_JWK)
    mockGetKeyManagementConfig.mockResolvedValue(KEY_MANAGEMENT_CONFIG_WITH_SERVICE)
    mockGetOrganizationLifecycle.mockResolvedValue({ planTier: 'community' })
    mockCreateIssuerProfile.mockResolvedValue({ id: 'profile-new' })
    mockPublishServiceToJwks.mockResolvedValue({})
    mockPublishServiceToDidVm.mockResolvedValue({})
  })

  it('renders the DID method selection step on first load', async () => {
    renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a DID method')).toBeInTheDocument()
    })

    expect(screen.getByText('did:web')).toBeInTheDocument()
    expect(screen.getByText('did:jwk')).toBeInTheDocument()
    expect(screen.getByText('did:key')).toBeInTheDocument()
  })

  it('Next button is disabled until a DID method is selected', async () => {
    renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a DID method')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  })

  it('Next button enables after a DID method is selected', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a DID method')).toBeInTheDocument()
    })

    await user.click(screen.getByText('did:jwk'))

    expect(screen.getByRole('button', { name: 'Next' })).not.toBeDisabled()
  })

  it('shows blocking preflight screen when no signing service is registered', async () => {
    mockGetKeyManagementConfig.mockResolvedValue({
      ...KEY_MANAGEMENT_CONFIG_WITH_SERVICE,
      services: [],
      default_service_id: null,
    })

    renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Setup required')).toBeInTheDocument()
    })

    expect(screen.getByText('No signing service registered')).toBeInTheDocument()
    expect(screen.queryByText('Choose a DID method')).not.toBeInTheDocument()
  })

  it('advances to Key source step after selecting did:jwk and clicking Next', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a DID method')).toBeInTheDocument()
    })

    await user.click(screen.getByText('did:jwk'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(screen.getByText('Key source')).toBeInTheDocument()
    })
  })

  it('creates an issuer profile for did:jwk using an existing key', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => expect(screen.getByText('Choose a DID method')).toBeInTheDocument())

    // Step 0: choose did:jwk
    await user.click(screen.getByText('did:jwk'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 1: use existing key
    await waitFor(() => expect(screen.getByText('Key source')).toBeInTheDocument())
    await user.click(screen.getByText('Use existing key from KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 2: select the key from card list
    await waitFor(() => expect(screen.getByText('Test issuer key')).toBeInTheDocument())
    await user.click(screen.getByText('Test issuer key'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 3: DID configuration (auto-derived, no required input)
    await waitFor(() => expect(screen.getByText('did:jwk configuration')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 4: Review & publish
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create identity' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Create identity' }))

    await waitFor(() => {
      expect(mockCreateIssuerProfile).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer_did: expect.stringMatching(/^did:jwk:/),
          signing_service_id: 'managed-openbao-transit',
          signing_key_reference: 'cred-issuer-test-es256',
        }),
      )
    })
    expect(mockCreateSigningKey).not.toHaveBeenCalled()
  })

  it('creates a new key in KMS, refreshes inventory, then saves did:jwk issuer profile', async () => {
    const newKey = {
      id: 'key-new',
      provider_key_name: 'cred-issuer-new-key',
      name: 'New issuer key',
      status: 'active',
      public_jwk: EC_JWK,
    }
    mockCreateSigningKey.mockResolvedValue({ key: newKey })
    // First call: initial load. Second call: refresh after key creation.
    mockListSigningKeys
      .mockResolvedValueOnce(SIGNING_KEYS_WITH_JWK)
      .mockResolvedValue({
        keys: [newKey],
        domain_config: SIGNING_KEYS_WITH_JWK.domain_config,
      })

    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => expect(screen.getByText('Choose a DID method')).toBeInTheDocument())

    // Step 0: choose did:jwk
    await user.click(screen.getByText('did:jwk'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 1: create new key
    await waitFor(() => expect(screen.getByText('Key source')).toBeInTheDocument())
    await user.click(screen.getByText('Create new key in KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 2: key configuration — fill in key name
    await waitFor(() => expect(screen.getByRole('textbox', { name: /key name/i })).toBeInTheDocument())
    const keyNameField = screen.getByRole('textbox', { name: /key name/i })
    await user.clear(keyNameField)
    await user.type(keyNameField, 'New issuer key')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 3: DID configuration
    await waitFor(() => expect(screen.getByText('did:jwk configuration')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 4: Review & publish
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create identity' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Create identity' }))

    await waitFor(() => {
      expect(mockCreateSigningKey).toHaveBeenCalledWith(
        expect.objectContaining({
          service_id: 'managed-openbao-transit',
          name: 'New issuer key',
          algorithm: 'ES256',
        }),
      )
      // listSigningKeys called on mount AND after key creation to refresh inventory
      expect(mockListSigningKeys).toHaveBeenCalledTimes(2)
      expect(mockCreateIssuerProfile).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer_did: expect.stringMatching(/^did:jwk:/),
        }),
      )
    })
  })

  it('recommends and enforces a compatible DID method for existing keys without public JWK', async () => {
    mockListSigningKeys.mockResolvedValue({
      keys: [
        {
          id: 'key-no-jwk',
          provider_key_name: 'no-pubkey',
          name: 'No pubkey key',
          status: 'active',
          // No public_jwk, no publicKeyJwk
        },
      ],
      domain_config: {
        public_domain: 'beta.example.com',
        issuer_base_url: 'https://beta.example.com',
      },
    })

    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new?prefill_key_id=key-no-jwk'],
    })

    await waitFor(() => expect(screen.getByText('Choose a DID method')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText(/Recommended for this key and compliance target: did:web/i)).toBeInTheDocument())

    await user.click(screen.getByText('did:jwk'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => expect(screen.getByText('Key source')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => expect(screen.getByText('No pubkey key')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => expect(screen.getByText('did:web configuration')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => expect(screen.getByRole('button', { name: 'Create identity' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Create identity' }))

    await waitFor(() => {
      expect(mockCreateIssuerProfile).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer_did: expect.stringMatching(/^did:web:/),
          signing_key_reference: 'no-pubkey',
        }),
      )
    })
  })

  it('publishes DID document and creates issuer profile for did:web', async () => {
    const { user } = renderWithRouter(<IssuerIdentityWizard />, {
      initialEntries: ['/console/org/deploy/issuer-identity/new'],
    })

    await waitFor(() => expect(screen.getByText('Choose a DID method')).toBeInTheDocument())

    // Step 0: choose did:web
    await user.click(screen.getByText('did:web'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 1: use existing key
    await waitFor(() => expect(screen.getByText('Key source')).toBeInTheDocument())
    await user.click(screen.getByText('Use existing key from KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 2: select key
    await waitFor(() => expect(screen.getByText('Test issuer key')).toBeInTheDocument())
    await user.click(screen.getByText('Test issuer key'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 3: DID configuration (did:web shows domain/path fields)
    await waitFor(() => expect(screen.getByText('did:web configuration')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Next' }))

    // Step 4: Review & publish
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create identity' })).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Create identity' }))

    await waitFor(() => {
      expect(mockPublishServiceToDidVm).toHaveBeenCalledWith(
        'managed-openbao-transit',
        undefined,
        expect.objectContaining({
          did_id: expect.stringMatching(/^did:web:/),
        }),
      )
      expect(mockCreateIssuerProfile).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer_did: expect.stringMatching(/^did:web:/),
        }),
      )
    })
  })
})
