import d10Controls from '../../../../../scripts/d10_ui_controls.json'
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
      config_revision: '"r-e4195bec-8a3a-43d5-828d-c7b5a0c4921c"',
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
          ca_cert_file: '/run/secrets/existing-transit-ca',
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

  it('D10 adapter controls match the rendered production OpenBao registration and review', async () => {
    mockGetKeyManagementConfig.mockResolvedValue({
      services: [{id:'previous',service_type:'openbao-transit',key_reference:'reserved-key'}],
      default_service_id:'previous',service_type_catalog:[],
      key_reference_purposes:{previous:{'reserved-key':['lti_tool_signing']}},
      type_defaults:{lti_tool_signing:'previous'},format_defaults:{'jwt':'previous'},
    })
    const { user } = renderWithRouter(<KeyManagementServiceWizard />)
    await user.click(await screen.findByRole(d10Controls.kmsProvider.role, { name: d10Name('kmsProvider') }))
    await user.click(screen.getByRole(d10Controls.next.role, { name: d10Name('next') }))
    for (const [key, value] of [
      ['kmsServiceName', 'D10 component contract'], ['kmsUrl', 'https://kms.internal.company'],
      ['kmsMount', 'transit'], ['kmsToken', 'generated-component-control-only'],
      ['kmsNamespace', 'customer-namespace'], ['kmsCaFile', '/run/secrets/customer-ca'],
    ] as const) {
      const input = screen.getByLabelText(d10Name(key))
      await user.clear(input)
      await user.type(input, value)
    }
    expect(screen.getByLabelText(d10Name('kmsToken'))).toHaveAttribute('type', 'password')
    await user.click(screen.getByRole(d10Controls.next.role, { name: d10Name('next') }))
    const keyInput = screen.getByLabelText(d10Name('kmsKey'))
    expect(keyInput).toBeRequired()
    await user.type(keyInput, 'existing-external-key')
    for (const key of ['kmsIssuerPurpose', 'kmsVerifierPurpose', 'kmsDefault'] as const) {
      const control = screen.getByRole(d10Controls[key].role, { name: d10Name(key), exact: key === 'kmsDefault' })
      if (!(control as HTMLInputElement).checked) await user.click(control)
      expect(control).toBeChecked()
    }
    expect(screen.queryByRole('checkbox', { name: d10Name('kmsDefault'), exact: true })).not.toBeInTheDocument()
    await user.click(screen.getByRole(d10Controls.next.role, { name: d10Name('next') }))
    expect(await screen.findByRole('heading', { name: 'Review' })).toBeInTheDocument()
    expect(screen.queryByText('generated-component-control-only')).not.toBeInTheDocument()
    await user.click(screen.getByRole(d10Controls.kmsRegister.role, { name: d10Name('kmsRegister') }))
    await waitFor(() => expect(mockUpdateKeyManagementConfig).toHaveBeenCalledTimes(1))
    const payload = mockUpdateKeyManagementConfig.mock.calls[0][0]
    expect(payload.organization_id).toBe('org-123')
    const registered = payload.services.find((service: {name: string}) => service.name === 'D10 component contract')
    expect(payload.default_service_id).toBe(registered.id)
    expect(payload.key_reference_purposes).toEqual({
      previous:{'reserved-key':['lti_tool_signing']},
      [registered.id]:{'existing-external-key':['vc_jwt_issuer','oid4vp_request_signing']},
    })
    expect(payload.type_defaults).toEqual({lti_tool_signing:'previous'})
    expect(payload.format_defaults).toEqual({'jwt':'previous'})
    expect(screen.getByText(/then create an issuer identity with its public DID and signing compatibility/i)).toBeInTheDocument()
    expect(screen.queryByText(/choose.*Use existing key from KMS/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Use managed OpenBao key creation' })).not.toBeInTheDocument()
    expect(registered).toMatchObject({ service_type: 'openbao-transit', key_reference: 'existing-external-key',
      ca_cert_file: '/run/secrets/customer-ca', key_purposes: expect.arrayContaining(['vc_jwt_issuer', 'oid4vp_request_signing']) })
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
    expect(screen.getByText(/web identity, container credentials, or EC2 metadata/i)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /key arn/i }), 'arn:aws:kms:us-west-2:123456789012:key/abc')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument()
    })

    mockValidateKeyManagementService.mockResolvedValueOnce({
      ok: false,
      checks: [{ name: 'Signing key state', status: 'fail', detail: 'The key is disabled.' }],
    })
    await user.click(screen.getByRole('button', { name: 'Register service' }))
    await screen.findByText('Key management service validation failed. Review the checks before registering.')
    expect(mockUpdateKeyManagementConfig).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Register service' }))

    await waitFor(() => {
      expect(mockUpdateKeyManagementConfig).toHaveBeenCalledTimes(1)
    })

    const payload = mockUpdateKeyManagementConfig.mock.calls[0][0]
    expect(payload.organization_id).toBe('org-123')
    expect(payload.default_service_id).toBeTruthy()
    expect(payload.config_revision).toBe('"r-e4195bec-8a3a-43d5-828d-c7b5a0c4921c"')
    expect(mockValidateKeyManagementService).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-123', service_type: 'aws-kms', live_probe: true,
      key_reference: 'arn:aws:kms:us-west-2:123456789012:key/abc',
    }))
    expect(payload.services).toHaveLength(2)
    expect(payload.services[0].ca_cert_file).toBe('/run/secrets/existing-transit-ca')
    expect(payload.services[1]).toMatchObject({
      name: 'Production AWS KMS',
      service_type: 'aws-kms',
      provider: 'aws',
      protocol: 'aws-kms',
      region: 'us-west-2',
      auth_mode: 'iam_role',
      auth_reference: '',
      key_reference: 'arn:aws:kms:us-west-2:123456789012:key/abc',
    })

    expect(screen.getByText('Signing service registered')).toBeInTheDocument()
    expect(screen.getByText(/create or verify the signing key in the KMS provider you just registered/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create issuer identity' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Use managed OpenBao key creation' })).not.toBeInTheDocument()
  })

  it('submits structured AWS credentials without exposing them in review', async () => {
    const { user } = renderWithRouter(<KeyManagementServiceWizard />, {
      initialEntries: ['/console/org/deploy/signing-keys/services/new'],
    })
    await screen.findByText('Choose a key management service')
    await user.click(screen.getByText('AWS KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /service name/i }), 'AWS access key signer')
    await user.type(screen.getByRole('textbox', { name: /region \/ location/i }), 'us-west-2')
    await user.click(screen.getByRole('combobox', { name: 'Authentication mode' }))
    await user.click(screen.getByRole('option', { name: 'Access key' }))
    await user.type(screen.getByRole('textbox', { name: 'Access key ID' }), 'AKIAEXAMPLE')
    await user.type(screen.getByLabelText(/Secret access key/), 'aws-secret')
    expect(screen.getByLabelText(/Secret access key/)).toHaveAttribute('type', 'password')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /key arn/i }), 'arn:aws:kms:us-west-2:123456789012:key/abc')
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(screen.getByText('Authentication details: Configured (hidden)')).toBeInTheDocument()
    expect(screen.queryByText(/aws-secret/)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Register service' }))
    await waitFor(() => expect(mockUpdateKeyManagementConfig).toHaveBeenCalledTimes(1))
    const service = mockUpdateKeyManagementConfig.mock.calls[0][0].services[1]
    expect(service.auth_mode).toBe('access_key')
    expect(JSON.parse(service.auth_reference)).toEqual({
      access_key_id: 'AKIAEXAMPLE', secret_access_key: 'aws-secret',
    })
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
    const caInput = screen.getByRole('textbox', { name: /TLS CA certificate file/i })
    expect(caInput).not.toBeRequired()
    await user.type(caInput, '/run/secrets/customer-transit-ca')
    expect(screen.getByText(/already mounted on the signing server/i)).toBeInTheDocument()
    const mountInput = screen.getByRole('textbox', { name: /transit mount/i })
    await user.clear(mountInput)
    await user.type(mountInput, 'marty-transit')
    await user.type(screen.getByLabelText(/transit token/i), 'vault-token')
    expect(screen.getByLabelText(/transit token/i)).toHaveAttribute('type', 'password')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.type(screen.getByRole('textbox', { name: /key reference/i }), 'cred-issuer-prod')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument()
    })
    expect(screen.getByText('Authentication details: Configured (hidden)')).toBeInTheDocument()
    expect(screen.queryByText(/Authentication details: vault-token/)).not.toBeInTheDocument()
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
      ca_cert_file: '/run/secrets/customer-transit-ca',
      mount: 'marty-transit',
      auth_reference: 'vault-token',
      key_reference: 'cred-issuer-prod',
    }))
    expect(await screen.findByText('Provider connectivity')).toBeInTheDocument()
    expect(screen.getByText('Connected to signer endpoint.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Register service' }))
    await waitFor(() => expect(mockUpdateKeyManagementConfig).toHaveBeenCalledTimes(1))
    expect(mockUpdateKeyManagementConfig.mock.calls[0][0].services[1].ca_cert_file).toBe('/run/secrets/customer-transit-ca')
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

  it('offers ES512 for CSCA key services while keeping other purposes constrained', async () => {
    const { user } = renderWithRouter(<KeyManagementServiceWizard />, {
      initialEntries: ['/console/org/deploy/signing-keys/services/new'],
    })

    await waitFor(() => {
      expect(screen.getByText('Choose a key management service')).toBeInTheDocument()
    })
    await user.click(screen.getByText('AWS KMS'))
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await user.type(screen.getByRole('textbox', { name: /service name/i }), 'P-521 CSCA')
    await user.type(screen.getByRole('textbox', { name: /region \/ location/i }), 'us-east-1')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.click(screen.getByLabelText('ES512'))
    await user.click(screen.getByLabelText('ES256'))

    expect(screen.getByRole('checkbox', { name: /CSCA \/ IACA root authority/i })).toBeEnabled()
    expect(screen.getByRole('checkbox', { name: /VC JWT \/ SD-JWT issuer/i })).toBeDisabled()
  })
})

const d10Name = (key: keyof typeof d10Controls) => {
  const definition = d10Controls[key] as { regex?: string; name?: string }
  return definition.regex ? new RegExp(definition.regex, 'i') : definition.name!
}
