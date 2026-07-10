import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import KeyManagementServiceWizard from './KeyManagementServiceWizard'

const {
  mockGetKeyManagementConfig,
  mockUpdateKeyManagementConfig,
  mockValidateKeyManagementService,
  mockShowNotification,
  mockUseConsole,
} = vi.hoisted(() => ({
  mockGetKeyManagementConfig: vi.fn(),
  mockUpdateKeyManagementConfig: vi.fn(),
  mockValidateKeyManagementService: vi.fn(),
  mockShowNotification: vi.fn(),
  mockUseConsole: vi.fn(),
}))

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    getKeyManagementConfig: (...args: unknown[]) => mockGetKeyManagementConfig(...args),
    updateKeyManagementConfig: (...args: unknown[]) => mockUpdateKeyManagementConfig(...args),
    validateKeyManagementService: (...args: unknown[]) => mockValidateKeyManagementService(...args),
  },
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

describe('KeyManagementServiceWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConsole.mockReturnValue({
      activeOrgId: 'org-123',
    })
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
        },
      ],
      service_type_catalog: [
        {
          id: 'aws-kms',
          label: 'AWS KMS',
          description: 'Register a customer-managed AWS KMS key for remote signing.',
          provider: 'aws',
          protocol: 'aws-kms',
          category: 'cloud-kms',
          auth_modes: ['iam_role', 'access_key'],
          connection_fields: ['region'],
          key_reference_label: 'Key ARN',
          supports_inventory: false,
        },
        {
          id: 'custom-transit-compatible',
          label: 'Custom Transit-Compatible Service',
          description: 'Any service that implements the transit-compatible signing protocol Marty supports.',
          provider: 'custom',
          protocol: 'vault-transit-compatible',
          category: 'custom',
          auth_modes: ['token', 'mtls'],
          connection_fields: ['endpoint', 'mount', 'namespace'],
          key_reference_label: 'Key reference',
          supports_inventory: false,
        },
      ],
    })
    mockUpdateKeyManagementConfig.mockResolvedValue({ ok: true })
    mockValidateKeyManagementService.mockResolvedValue({
      ok: true,
      checks: [
        {
          name: 'Provider connectivity',
          status: 'pass',
          detail: 'Connected to signer endpoint.',
          source: 'live',
        },
      ],
    })
  })

  it('registers a new AWS KMS signing service through the wizard', async () => {
    const { user } = renderWithRouter(<KeyManagementServiceWizard />, {
      initialEntries: ['/console/org/deploy/signing-keys/services/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a key management service')).toBeInTheDocument()
    })
    expect(mockGetKeyManagementConfig).toHaveBeenCalledWith({ organization_id: 'org-123' })

    await user.click(screen.getByText('AWS KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /service name/i }), 'Production AWS KMS')
    await user.type(screen.getByRole('textbox', { name: /region \/ location/i }), 'us-west-2')
    await user.type(screen.getByRole('textbox', { name: /credential reference/i }), 'aws-role/signing')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /key arn/i }), 'arn:aws:kms:us-west-2:123456789012:key/abc')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Register service' }))

    await waitFor(() => {
      expect(mockUpdateKeyManagementConfig).toHaveBeenCalledTimes(1)
    })

    const payload = mockUpdateKeyManagementConfig.mock.calls[0][0]
    expect(payload.organization_id).toBe('org-123')
    expect(payload.default_service_id).toBeTruthy()
    expect(payload.services).toHaveLength(2)
    expect(payload.services[1]).toMatchObject({
      name: 'Production AWS KMS',
      service_type: 'aws-kms',
      provider: 'aws',
      protocol: 'aws-kms',
      region: 'us-west-2',
      key_reference: 'arn:aws:kms:us-west-2:123456789012:key/abc',
    })

    expect(screen.getByText('Signing service registered')).toBeInTheDocument()
    expect(screen.getByText(/create or verify the signing key in the KMS provider you just registered/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create issuer identity' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Use managed OpenBao key creation' })).toBeInTheDocument()
  })

  it('runs backend validation checks in the review step', async () => {
    const { user } = renderWithRouter(<KeyManagementServiceWizard />, {
      initialEntries: ['/console/org/deploy/signing-keys/services/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a key management service')).toBeInTheDocument()
    })

    await user.click(screen.getByText('Custom Transit-Compatible Service'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /service name/i }), 'Transit signer')
    await user.type(screen.getByRole('textbox', { name: /service url/i }), 'https://signer.example.com')
    const mountInput = screen.getByRole('textbox', { name: /transit mount/i })
    await user.clear(mountInput)
    await user.type(mountInput, 'marty-transit')
    await user.type(screen.getByRole('textbox', { name: /credential reference/i }), 'vault-token')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /key reference/i }), 'cred-issuer-prod')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument()
    })
    expect(screen.getByText((content) => content.includes('vault secrets enable -path=marty-transit transit'))).toBeInTheDocument()
    expect(screen.getByText((content) => content.includes('vault write -f marty-transit/keys/cred-issuer-prod type=ecdsa-p256'))).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Validate connection' }))

    await waitFor(() => {
      expect(mockValidateKeyManagementService).toHaveBeenCalledTimes(1)
    })

    expect(mockValidateKeyManagementService).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-123',
      service_type: 'custom-transit-compatible',
      endpoint: 'https://signer.example.com',
      mount: 'marty-transit',
      auth_reference: 'vault-token',
      key_reference: 'cred-issuer-prod',
    }))
    expect(await screen.findByText('Provider connectivity')).toBeInTheDocument()
    expect(screen.getByText('Connected to signer endpoint.')).toBeInTheDocument()
  })

  it('disables incompatible key purposes for selected algorithms', async () => {
    const { user } = renderWithRouter(<KeyManagementServiceWizard />, {
      initialEntries: ['/console/org/deploy/signing-keys/services/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a key management service')).toBeInTheDocument()
    })

    await user.click(screen.getByText('AWS KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /service name/i }), 'Algo policy service')
    await user.type(screen.getByRole('textbox', { name: /region \/ location/i }), 'us-east-1')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Key access' })).toBeInTheDocument()
    })

    await user.click(screen.getByLabelText('RS256'))
    await user.click(screen.getByLabelText('ES256'))

    expect(screen.getByRole('checkbox', { name: /mDoc document signer/i })).toBeDisabled()
  })
})
