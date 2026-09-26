import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import { useLocation } from 'react-router'
import SigningKeysPage from './SigningKeysPage'

const {
  mockCan,
  mockRoles,
  mockShowNotification,
  mockListSigningKeys,
  mockCreateSigningKey,
  mockRotateSigningKey,
  mockRotateServiceKey,
  mockGetServiceCertificate,
  mockGenerateServiceCsr,
  mockDeleteSigningKey,
  mockGetKeyManagementConfig,
  mockUpdateKeyManagementConfig,
  mockUseConsole,
} = vi.hoisted(() => ({
  mockCan: vi.fn(),
  mockRoles: vi.fn(),
  mockShowNotification: vi.fn(),
  mockListSigningKeys: vi.fn(),
  mockCreateSigningKey: vi.fn(),
  mockRotateSigningKey: vi.fn(),
  mockRotateServiceKey: vi.fn(),
  mockGetServiceCertificate: vi.fn(),
  mockGenerateServiceCsr: vi.fn(),
  mockDeleteSigningKey: vi.fn(),
  mockGetKeyManagementConfig: vi.fn(),
  mockUpdateKeyManagementConfig: vi.fn(),
  mockUseConsole: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
  initReactI18next: {
    type: '3rdParty',
    init: () => {},
  },
}))

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listSigningKeys: (...args: unknown[]) => mockListSigningKeys(...args),
    createSigningKey: (...args: unknown[]) => mockCreateSigningKey(...args),
    rotateSigningKey: (...args: unknown[]) => mockRotateSigningKey(...args),
    rotateServiceKey: (...args: unknown[]) => mockRotateServiceKey(...args),
    getServiceCertificate: (...args: unknown[]) => mockGetServiceCertificate(...args),
    generateServiceCsr: (...args: unknown[]) => mockGenerateServiceCsr(...args),
    deleteSigningKey: (...args: unknown[]) => mockDeleteSigningKey(...args),
    getKeyManagementConfig: (...args: unknown[]) => mockGetKeyManagementConfig(...args),
    updateKeyManagementConfig: (...args: unknown[]) => mockUpdateKeyManagementConfig(...args),
  },
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    can: mockCan,
    roles: mockRoles(),
    getPermissionMessage: () => 'permission denied',
  }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

describe('SigningKeysPage', () => {
  const CurrentPath = () => <span data-testid="current-path">{useLocation().pathname}</span>
  const configureRotatableService = () => mockGetKeyManagementConfig.mockResolvedValue({
    supports_native_key_management: false,
    default_service_id: 'svc-transit',
    services: [{
      id: 'svc-transit', name: 'Registered OpenBao', service_type: 'openbao-transit',
      provider: 'openbao', endpoint: 'http://openbao:8200', mount: 'transit',
      key_reference: 'registered-key', key_aliases: ['registered-key'],
      algorithms: ['ES256'], managed: false, read_only: false,
    }],
    service_type_catalog: [],
  })
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConsole.mockReturnValue({
      activeOrgId: 'org-123',
    })
    mockRoles.mockReturnValue([])
    mockCan.mockImplementation((resource: string, action: string) => {
      if (resource === 'signing-key' && (action === 'create' || action === 'delete')) {
        return true
      }

      return false
    })
    mockListSigningKeys.mockResolvedValue({
      keys: [],
      provider_metadata: {
        provider: 'openbao',
        status: 'configured',
        supports_upload: false,
        supports_delete: false,
        supports_rotation: false,
      },
      domain_config: {
        public_domain: 'beta.elevenidllc.com',
        issuer_base_url: 'https://beta.elevenidllc.com',
      },
    })
    mockCreateSigningKey.mockResolvedValue({ id: 'key_new' })
    mockRotateSigningKey.mockResolvedValue({ id: 'key_new' })
    mockRotateServiceKey.mockResolvedValue({ ok: true })
    mockGetServiceCertificate.mockRejectedValue(new Error('No certificate'))
    mockGenerateServiceCsr.mockResolvedValue({ csr_pem: '-----BEGIN CERTIFICATE REQUEST-----' })
    mockDeleteSigningKey.mockResolvedValue({ ok: true })
    mockGetKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'managed-openbao-transit',
      services: [
        {
          id: 'managed-openbao-transit',
          name: 'Marty managed OpenBao transit',
          service_type: 'openbao-transit',
          provider: 'openbao',
          provider_label: 'OpenBao Transit',
          protocol: 'vault-transit',
          endpoint: 'http://openbao:8200',
          mount: 'transit',
          key_reference: 'cred-issuer-marty-es256',
          key_aliases: ['cred-issuer-marty-es256'],
          algorithms: ['ES256'],
          status: 'configured',
          managed: true,
          read_only: true,
          managed_by: 'Marty service stack',
          rotation_state: {
            last_rotated_at: '2026-04-21T12:30:00Z',
          },
        },
      ],
      service_type_catalog: [],
    })
    mockUpdateKeyManagementConfig.mockResolvedValue({ ok: true })
  })

  it('shows a service-registration CTA instead of native upload when native key management is disabled', async () => {
    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('No signing keys discovered yet')).toBeInTheDocument()
    })

    expect(mockListSigningKeys).toHaveBeenCalledWith({ organization_id: 'org-123' })
    expect(mockGetKeyManagementConfig).toHaveBeenCalledWith({ organization_id: 'org-123' })
    expect(screen.getByRole('button', { name: 'Register key management service' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Create issuer identity' })).toBeInTheDocument()
    expect(screen.getByText(/Create an issuer identity and choose "Create new key in KMS"/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'deploy.signingKeys.uploadKey' })).not.toBeInTheDocument()
    expect(screen.getByText('Elevenidllc managed OpenBao transit')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Rotate key' })).not.toBeInTheDocument()
  })

  it('routes managed passport CSR creation to the issuer identity instead of a shared service key', async () => {
    mockGetKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'managed-openbao-transit',
      services: [{
        id: 'managed-openbao-transit', name: 'Marty managed OpenBao transit',
        service_type: 'openbao-transit', provider: 'openbao',
        key_purposes: ['csca', 'x509_doc_signer'], algorithms: ['ES256'],
        managed: true, read_only: true, status: 'configured',
      }],
      service_type_catalog: [],
    })
    const { user } = renderWithRouter(<><SigningKeysPage /><CurrentPath /></>, {
      initialEntries: ['/console/org/deploy/key-management'],
    })
    await screen.findByText('Elevenidllc managed OpenBao transit')
    await user.click(screen.getByRole('button', { name: 'Certificate' }))
    await user.click(screen.getByRole('button', { name: 'Generate CSR from issuer identity' }))
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/deploy/issuer-identity')
  })

  it('requires an explicit registered-service CSR subject and sends only public fields', async () => {
    mockGetKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'service-a',
      services: [{
        id: 'service-a', name: 'Registered signer', service_type: 'openbao-transit',
        provider: 'openbao', key_reference: 'server-side-only', algorithms: ['ES256'],
        key_purposes: ['csca'],
        managed: false, read_only: false, status: 'registered',
      }],
      service_type_catalog: [],
    })
    const { user } = renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })
    await screen.findByText('Registered signer')
    await user.click(screen.getByRole('button', { name: 'Certificate' }))
    const csrButton = screen.getByRole('button', { name: 'Generate CSR from service public key' })
    expect(csrButton).toBeDisabled()
    await user.type(screen.getByLabelText('Subject country (two-letter ISO code)'), 'us')
    await user.type(screen.getByLabelText('Subject organization'), 'Example Org')
    expect(csrButton).toBeEnabled()
    await user.click(csrButton)
    await waitFor(() => expect(mockGenerateServiceCsr).toHaveBeenCalledWith('service-a', {
      organization_id: 'org-123', country: 'US', organization: 'Example Org', common_name: 'Registered signer',
    }))
    expect(mockGenerateServiceCsr.mock.calls[0][1]).not.toHaveProperty('key_reference')
  })

  it('renders the services registry view with managed and registered services', async () => {
    mockGetKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'managed-openbao-transit',
      services: [
        {
          id: 'managed-openbao-transit',
          name: 'Marty managed OpenBao transit',
          service_type: 'openbao-transit',
          provider: 'openbao',
          provider_label: 'OpenBao Transit',
          protocol: 'vault-transit',
          endpoint: 'http://openbao:8200',
          mount: 'transit',
          key_reference: 'cred-issuer-marty-es256',
          key_aliases: ['cred-issuer-marty-es256'],
          algorithms: ['ES256'],
          status: 'configured',
          managed: true,
          read_only: true,
          managed_by: 'Marty service stack',
        },
        {
          id: 'svc-aws',
          name: 'AWS signing key',
          service_type: 'aws-kms',
          provider: 'aws',
          provider_label: 'AWS KMS',
          protocol: 'aws-kms',
          region: 'us-west-2',
          key_reference: 'arn:aws:kms:us-west-2:123456789012:key/example',
          key_aliases: ['alias/marty-issuer'],
          algorithms: ['ES256', 'RS256'],
          status: 'registered',
          managed: false,
          read_only: false,
        },
      ],
      service_type_catalog: [],
    })

    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('Elevenidllc managed OpenBao transit')).toBeInTheDocument()
    })

    expect(screen.getByText('AWS signing key')).toBeInTheDocument()
    expect(screen.getByText('Default signer')).toBeInTheDocument()
    expect(screen.getAllByText(/Last rotated:/)).not.toHaveLength(0)
    expect(screen.getByRole('button', { name: 'Make default' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument()
  })

  it('reports rotation completion after rotating a service key', async () => {
    vi.spyOn(window, 'confirm').mockImplementation(() => true)
    configureRotatableService()

    const { user } = renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('Registered OpenBao')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Rotate key' }))

    await waitFor(() => {
      expect(mockRotateServiceKey).toHaveBeenCalledWith('svc-transit', { organization_id: 'org-123' })
      expect(mockShowNotification).toHaveBeenCalledWith('Key rotation completed successfully.', 'success')
    })
  })

  it('warns when KMS rotation succeeds but public key publication fails', async () => {
    vi.spyOn(window, 'confirm').mockImplementation(() => true)
    configureRotatableService()
    mockRotateServiceKey.mockResolvedValue({ ok: true, publication: { jwks: false, did: false } })
    const { user } = renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })
    await waitFor(() => {
      expect(screen.getByText('Registered OpenBao')).toBeInTheDocument()
    })
    await user.click(screen.getByRole('button', { name: 'Rotate key' }))
    await waitFor(() => {
      expect(mockShowNotification).toHaveBeenCalledWith(
        expect.stringContaining('public key publication is incomplete'),
        'warning',
      )
    })
  })

  it('org admins can register additional key management services without signing-key:create', async () => {
    mockCan.mockReturnValue(false)
    mockRoles.mockReturnValue([
      { id: 'role-admin', name: 'admin', display_name: 'Administrator' },
    ])
    mockGetKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'managed-openbao-transit',
      services: [
        {
          id: 'managed-openbao-transit',
          name: 'Marty managed OpenBao transit',
          service_type: 'openbao-transit',
          provider: 'openbao',
          provider_label: 'OpenBao Transit',
          protocol: 'vault-transit',
          endpoint: 'http://openbao:8200',
          mount: 'transit',
          key_reference: 'cred-issuer-marty-es256',
          key_aliases: ['cred-issuer-marty-es256'],
          algorithms: ['ES256'],
          status: 'configured',
          managed: true,
          read_only: true,
          managed_by: 'Marty service stack',
        },
        {
          id: 'svc-secondary',
          name: 'Secondary KMS',
          service_type: 'aws-kms',
          provider: 'aws',
          provider_label: 'AWS KMS',
          protocol: 'aws-kms',
          region: 'us-west-2',
          key_reference: 'arn:aws:kms:us-west-2:123456789012:key/secondary',
          key_aliases: ['alias/marty-secondary'],
          algorithms: ['ES256'],
          status: 'registered',
          managed: false,
          read_only: false,
        },
      ],
      service_type_catalog: [],
    })

    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('Elevenidllc managed OpenBao transit')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Register key management service' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Make default' })).toBeInTheDocument()
  })

  it('bootstrapped org_admin role strings can register key management services', async () => {
    mockCan.mockReturnValue(false)
    mockRoles.mockReturnValue(['org_admin'])

    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('Elevenidllc managed OpenBao transit')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Register key management service' })).toBeEnabled()
  })

  it('non-admin users can inspect the service registry and still open registration wizard entry', async () => {
    mockCan.mockReturnValue(false)
    mockRoles.mockReturnValue([])

    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('Elevenidllc managed OpenBao transit')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Register key management service' })).toBeEnabled()
    expect(screen.getByText('Service registration is available from this page. Updating or removing existing services may still require elevated permissions.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Make default' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument()
  })

  it('shows derived key purpose labels for DID issuer and X.509 document signer keys', async () => {
    mockListSigningKeys.mockResolvedValue({
      keys: [
        {
          id: 'key-did',
          provider_key_name: 'cred-issuer-marty-es256',
          name: 'Marty ES256 issuer key',
          algorithm: 'ES256',
          status: 'active',
          created_at: '2026-04-16T00:00:00Z',
        },
        {
          id: 'key-x509',
          provider_key_name: 'cred-dsc-marty-primary',
          name: 'Marty document signer key',
          algorithm: 'ES256',
          status: 'active',
          created_at: '2026-04-16T00:00:00Z',
        },
      ],
      provider_metadata: {
        provider: 'openbao',
        status: 'configured',
      },
      domain_config: {
        public_domain: 'beta.elevenidllc.com',
        issuer_base_url: 'https://beta.elevenidllc.com',
      },
    })

    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/key-management'],
    })

    await waitFor(() => {
      expect(screen.getByText('Marty ES256 issuer key')).toBeInTheDocument()
    })

    expect(screen.getByText('deploy.signingKeys.tableHeaders.purpose')).toBeInTheDocument()
    expect(screen.getByText('deploy.signingKeys.purposes.issuer')).toBeInTheDocument()
    expect(screen.getByText('deploy.signingKeys.purposes.x509')).toBeInTheDocument()
    expect(screen.getByText('deploy.signingKeys.associations.credentialIssuer')).toBeInTheDocument()
    expect(screen.getByText('deploy.signingKeys.associations.documentSigner')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Open service settings' })).not.toBeInTheDocument()
    expect(screen.getAllByText('Monitored only')).not.toHaveLength(0)
  })
})
