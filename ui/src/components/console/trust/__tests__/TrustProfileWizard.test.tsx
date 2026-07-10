/**
 * Integration Tests for Trust Profile Wizard
 * 
 * Tests complete wizard flow including:
 * - Step navigation
 * - Form validation
 * - Data persistence across steps
 * - API submission
 * - Success/error handling
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import TrustProfileWizard from '../TrustProfileWizard'

const mockListWallets = vi.fn()
const mockListSigningKeys = vi.fn()
const mockGetKeyManagementConfig = vi.fn()
const mockListIssuerProfiles = vi.fn()
const mockCreateIssuerProfile = vi.fn()

const TRANSLATIONS = {
  'wizards.trustProfile.title': 'Build Trust Profile',
  'wizards.trustProfile.description': 'Create a trust profile for credential verification.',
  'wizards.trustProfile.steps.basics': 'Basics',
  'wizards.trustProfile.steps.trustSources': 'Trust Sources',
  'wizards.trustProfile.steps.validationRules': 'Cryptographic Policy',
  'wizards.trustProfile.steps.review': 'Review & Activate',
  'wizards.trustProfile.buttons.cancel': 'Cancel',
  'wizards.trustProfile.buttons.back': 'Back',
  'wizards.trustProfile.buttons.next': 'Next',
  'wizards.trustProfile.buttons.skip': 'Skip',
  'wizards.trustProfile.buttons.submit': 'Create Trust Profile',
  'wizards.trustProfile.buttons.submitting': 'Submitting...',
  'wizards.trustProfile.success.title': 'Trust Profile Created!',
  'wizards.trustProfile.success.messageActive': 'Trust profile {{name}} created and activated.',
  'wizards.trustProfile.success.messageDraft': 'Trust profile {{name}} created as a draft.',
  'wizards.trustProfile.success.nextStep': 'Next steps',
  'wizards.trustProfile.success.redirecting': 'Redirecting...',
  'wizards.trustProfile.basicsStep.title': 'Basic Information',
  'wizards.trustProfile.basicsStep.description': 'Configure the core trust profile details.',
  'wizards.trustProfile.basicsStep.fields.name': 'Trust Profile Name',
  'wizards.trustProfile.basicsStep.fields.description': 'Description',
  'wizards.trustProfile.basicsStep.fields.frameworkType': 'Framework Type',
  'wizards.trustProfile.basicsStep.fields.supportedFormats': 'Supported Credential Formats *',
  'wizards.trustProfile.basicsStep.helpers.name': 'Enter a descriptive profile name.',
  'wizards.trustProfile.basicsStep.helpers.description': 'Optional description.',
  'wizards.trustProfile.basicsStep.helpers.frameworkType': 'Choose the verification framework.',
  'wizards.trustProfile.basicsStep.helpers.supportedFormats': 'Select supported credential formats.',
  'wizards.trustProfile.basicsStep.placeholders.name': 'Production Trust Profile',
  'wizards.trustProfile.basicsStep.recommendedChip': 'Recommended',
  'wizards.trustProfile.frameworkLabels.icao': 'ICAO',
  'wizards.trustProfile.frameworkLabels.aamva': 'AAMVA',
  'wizards.trustProfile.frameworkLabels.eudi': 'EUDI',
  'wizards.trustProfile.frameworkLabels.custom': 'Custom',
  'wizards.trustProfile.basicsStep.formatOptions.jwt_vc': 'JWT VC',
  'wizards.trustProfile.basicsStep.formatOptions.sd_jwt_vc': 'SD-JWT VC',
  'wizards.trustProfile.basicsStep.formatOptions.mdoc': 'mdoc',
  'wizards.trustProfile.basicsStep.formatOptions.ldp_vc': 'JSON-LD VC',
  'wizards.trustProfile.trustSourcesStep.title': 'Trust Sources',
  'wizards.trustProfile.trustSourcesStep.optionalChip': 'Optional',
  'wizards.trustProfile.trustSourcesStep.description': 'Add trusted issuer DIDs.',
  'wizards.trustProfile.trustSourcesStep.infoAlert.body': 'Pinned issuers become trusted sources in the backend.',
  'wizards.trustProfile.trustSourcesStep.infoAlert.skippingTitle': 'Skipping',
  'wizards.trustProfile.trustSourcesStep.infoAlert.skippingDescription': 'By default, an empty trust profile trusts no issuers. Turn on Allow any issuer below only if you intentionally want an open trust policy.',
  'wizards.trustProfile.trustSourcesStep.allowAllIssuers.label': 'Allow any issuer',
  'wizards.trustProfile.trustSourcesStep.allowAllIssuers.defaultDescription': 'Disabled by default. If you leave this off and do not add trust sources, the profile will trust no issuers.',
  'wizards.trustProfile.trustSourcesStep.allowAllIssuers.enabledDescription': 'This empty trust profile will accept credentials from any issuer that passes the configured cryptographic validation.',
  'wizards.trustProfile.trustSourcesStep.allowAllIssuers.disabledDescription': 'Explicit trust sources are configured. Remove them if you want this profile to fall back to a global issuer policy.',
  'wizards.trustProfile.trustSourcesStep.examplesTitle': 'Example DIDs',
  'wizards.trustProfile.trustSourcesStep.issuerDid.label': 'Issuer DID',
  'wizards.trustProfile.trustSourcesStep.issuerDid.placeholder': 'did:web:issuer.example.com',
  'wizards.trustProfile.trustSourcesStep.issuerDid.helper': 'Enter one DID per issuer.',
  'wizards.trustProfile.trustSourcesStep.addButton': 'Add',
  'wizards.trustProfile.trustSourcesStep.trustedIssuersTitle': '{{count}} trusted issuers',
  'wizards.trustProfile.trustSourcesStep.emptyState': 'No issuers added yet.',
  'wizards.trustProfile.trustSourcesStep.comingSoon.title': 'Coming soon.',
  'wizards.trustProfile.trustSourcesStep.comingSoon.description': 'Registry import will land later.',
  'wizards.trustProfile.validationRulesStep.title': 'Cryptographic Policy',
  'wizards.trustProfile.validationRulesStep.optionalChip': 'Optional',
  'wizards.trustProfile.validationRulesStep.description': 'Fine-tune validation requirements.',
  'wizards.trustProfile.validationRulesStep.defaultsAlert.title': 'Secure defaults',
  'wizards.trustProfile.validationRulesStep.defaultsAlert.description': 'Default settings are suitable for most deployments.',
  'wizards.trustProfile.validationRulesStep.frameworkLockedAlert.title': 'Signing algorithm selection is managed by the {{framework}} framework.',
  'wizards.trustProfile.validationRulesStep.frameworkLockedAlert.description': 'Switch to Custom framework to customize signing algorithm requirements.',
  'wizards.trustProfile.validationRulesStep.resetDefaults': 'Reset defaults',
  'wizards.trustProfile.validationRulesStep.allowedAlgorithms.title': 'Allowed Algorithms',
  'wizards.trustProfile.validationRulesStep.allowedAlgorithms.helper': 'Select accepted algorithms.',
  'wizards.trustProfile.validationRulesStep.allowedAlgorithms.helperLocked': 'This framework restricts signing algorithms. Choose Custom to edit them.',
  'wizards.trustProfile.validationRulesStep.advanced.toggle': '{{action}} advanced options',
  'wizards.trustProfile.validationRulesStep.advanced.hide': 'Hide',
  'wizards.trustProfile.validationRulesStep.advanced.show': 'Show',
  'wizards.trustProfile.validationRulesStep.keySize.label': 'Minimum key size',
  'wizards.trustProfile.validationRulesStep.keySize.helper': 'Applies to RSA keys.',
  'wizards.trustProfile.validationRulesStep.additionalSecurity.title': 'Additional security',
  'wizards.trustProfile.validationRulesStep.additionalSecurity.allowSelfSigned.label': 'Allow self-signed credentials',
  'wizards.trustProfile.validationRulesStep.additionalSecurity.allowSelfSigned.helper': 'Usually disabled.',
  'wizards.trustProfile.validationRulesStep.additionalSecurity.requireKeyUsage.label': 'Require key usage validation',
  'wizards.trustProfile.validationRulesStep.additionalSecurity.requireKeyUsage.helper': 'Recommended.',
  'wizards.trustProfile.reviewStep.title': 'Review & Activate',
  'wizards.trustProfile.reviewStep.description': 'Review configuration before creation.',
  'wizards.trustProfile.reviewStep.sections.basicInformation': 'Basic Information',
  'wizards.trustProfile.reviewStep.sections.trustSources': 'Trust Sources',
  'wizards.trustProfile.reviewStep.sections.validationRules': 'Cryptographic Policy',
  'wizards.trustProfile.reviewStep.actions.edit': 'Edit',
  'wizards.trustProfile.reviewStep.fields.profileName': 'Profile Name',
  'wizards.trustProfile.reviewStep.fields.description': 'Description',
  'wizards.trustProfile.reviewStep.fields.frameworkType': 'Framework Type',
  'wizards.trustProfile.reviewStep.fields.supportedFormats': 'Supported Formats',
  'wizards.trustProfile.reviewStep.fields.allowedAlgorithms': 'Allowed Algorithms',
  'wizards.trustProfile.reviewStep.fields.selfSignedCredentials': 'Self-signed credentials',
  'wizards.trustProfile.reviewStep.fields.minimumKeySize': 'Minimum key size',
  'wizards.trustProfile.reviewStep.fields.keyUsageValidation': 'Key usage validation',
  'wizards.trustProfile.reviewStep.values.notSet': 'Not set',
  'wizards.trustProfile.reviewStep.values.allowed': 'Allowed',
  'wizards.trustProfile.reviewStep.values.notAllowed': 'Not allowed',
  'wizards.trustProfile.reviewStep.values.bits': 'bits',
  'wizards.trustProfile.reviewStep.values.required': 'Required',
  'wizards.trustProfile.reviewStep.values.notRequired': 'Not required',
  'wizards.trustProfile.reviewStep.trustSourcesSummary.trustedIssuersConfigured': '{{count}} trusted issuers configured',
  'wizards.trustProfile.reviewStep.trustSourcesSummary.andMore': 'and {{count}} more',
  'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfigured': 'No trust sources are configured. This profile will trust no issuers until trust sources are added.',
  'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfiguredActive': 'This profile is set to activate immediately, but no trust sources are configured. Add a trusted issuer or explicitly allow any issuer before activating.',
  'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfiguredAllowAll': 'No trust sources are configured. This profile is explicitly set to trust any issuer that passes cryptographic validation.',
  'wizards.trustProfile.reviewStep.fields.revocationStrategy': 'Revocation Strategy',
  'wizards.trustProfile.reviewStep.fields.clockSkew': 'Clock Skew Tolerance',
  'wizards.trustProfile.reviewStep.fields.credentialFreshness': 'Credential Freshness',
  'wizards.trustProfile.reviewStep.fields.issuanceProtocol': 'Issuance Protocol',
  'wizards.trustProfile.reviewStep.fields.supportedWallets': 'Supported Wallets',
  'wizards.trustProfile.reviewStep.values.allCompatibleWallets': 'No wallet targeting configured',
  'wizards.trustProfile.reviewStep.activationExplanation.title': 'Activation',
  'wizards.trustProfile.reviewStep.activationExplanation.description': 'Choose whether to activate immediately.',
  'wizards.trustProfile.reviewStep.activateImmediately.label': 'Activate immediately',
  'wizards.trustProfile.reviewStep.activateImmediately.description': 'Enable this trust profile after creation.',
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key, options = {}) => {
      const template = TRANSLATIONS[key] || options.defaultValue || key
      return template.replace(/\{\{(.*?)\}\}/g, (_, token) => String(options[token.trim()] ?? ''))
    },
  }),
}))

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org-1',
  }),
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}))

vi.mock('../../../../services/walletRegistryApi', () => ({
  listWallets: (...args) => mockListWallets(...args),
}))

vi.mock('../../../../services/signingKeysApi', () => ({
  default: {
    listSigningKeys: (...args) => mockListSigningKeys(...args),
    getKeyManagementConfig: (...args) => mockGetKeyManagementConfig(...args),
    listIssuerProfiles: (...args) => mockListIssuerProfiles(...args),
    createIssuerProfile: (...args) => mockCreateIssuerProfile(...args),
  },
}))

// Mock navigation
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

describe('TrustProfileWizard', () => {
  const MSW_BASE = 'http://localhost:8000'
  let lastTrustProfileRequestBody: any = null
  let activatedTrustProfileId: string | null = null

  beforeEach(() => {
    vi.clearAllMocks()
    mockListWallets.mockResolvedValue([
      {
        id: 'wallet-1',
        name: 'Acme Wallet',
        supported_platforms: ['iOS', 'Android'],
      },
      {
        id: 'wallet-2',
        name: 'Contoso Wallet',
        supported_platforms: ['Web'],
      },
    ])
    mockListSigningKeys.mockResolvedValue({
      keys: [
        {
          id: 'key-1',
          provider_key_name: 'cred-issuer-test-es256',
          name: 'Test issuer key',
          status: 'active',
          public_jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'abc123',
            y: 'def456',
            kid: 'cred-issuer-test-es256',
          },
        },
      ],
      domain_config: {
        public_domain: 'beta.example.com',
        issuer_base_url: 'https://beta.example.com',
      },
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
          status: 'configured',
          managed: true,
        },
      ],
      domain_config: {
        public_domain: 'beta.example.com',
        issuer_base_url: 'https://beta.example.com',
      },
      service_type_catalog: [],
    })
    mockListIssuerProfiles.mockResolvedValue({ profiles: [] })
    mockCreateIssuerProfile.mockResolvedValue({
      id: 'issuer-profile-created',
      name: 'Managed issuer identity',
      issuer_did: 'did:jwk:created',
      signing_service_id: 'managed-openbao-transit',
      signing_key_reference: 'cred-issuer-test-es256',
      status: 'active',
    })
    lastTrustProfileRequestBody = null
    activatedTrustProfileId = null
    server.use(
      http.post(`${MSW_BASE}/v1/trust-profiles`, async ({ request }) => {
        const body = await request.json() as any
        lastTrustProfileRequestBody = body
        return HttpResponse.json({
          id: 'trust-profile-1',
          status: 'active',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
          ...body,
        }, { status: 201 })
      }),
      http.post(`${MSW_BASE}/v1/trust-profiles/:id/activate`, ({ params }) => {
        activatedTrustProfileId = params.id as string
        return HttpResponse.json({
          id: params.id,
          status: 'active',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        })
      }),
      http.post(`${MSW_BASE}/v1/trust-profiles/:id/issuers`, async ({ request, params }) => {
        const body = await request.json() as any
        return HttpResponse.json({
          id: 'issuer-link-1',
          trust_profile_id: params.id,
          status: 'active',
          ...body,
        }, { status: 201 })
      })
    )
  })

  const addTrustedIssuer = async (user) => {
    const issuerInput = screen.getByTestId('wizard.trustProfile.issuerDid')
    await user.type(issuerInput, 'did:web:issuer.example.com')
    await user.click(screen.getByTestId('wizard.trustProfile.addIssuer'))
  }

  const selectFramework = async (user, label) => {
    fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.frameworkTypeField')).getByRole('combobox'))
    await user.click(await screen.findByRole('option', { name: label }))
  }

  const goToValidationRulesStep = async (user) => {
    await user.click(screen.getByTestId('wizard.trustProfile.next'))

    await waitFor(() => {
      expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
    })

    await user.click(screen.getByTestId('wizard.trustProfile.skip'))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Cryptographic Policy' })).toBeInTheDocument()
    })
  }

  describe('initial render', () => {
    it('should render wizard with correct initial state', () => {
      render(<TrustProfileWizard />)

      // Check title
      expect(screen.getByText('Build Trust Profile')).toBeInTheDocument()

      // Check stepper shows all steps
      expect(screen.getByText('Basics')).toBeInTheDocument()
      expect(screen.getByText('Trust Sources')).toBeInTheDocument()
      expect(screen.getByText('Cryptographic Policy')).toBeInTheDocument()
      expect(screen.getByText('Review & Activate')).toBeInTheDocument()

      // Check initial step content
      expect(screen.getByText('Basic Information')).toBeInTheDocument()
      expect(screen.getByTestId('wizard.trustProfile.name')).toBeInTheDocument()

      // Check buttons
      expect(screen.getByTestId('wizard.trustProfile.cancel')).toBeInTheDocument()
      expect(screen.getByTestId('wizard.trustProfile.next')).toBeInTheDocument()
    })

    it('should have Next button disabled initially due to validation', () => {
      render(<TrustProfileWizard />)

      const nextButton = screen.getByTestId('wizard.trustProfile.next')
      expect(nextButton).toBeDisabled()
    })
  })

  describe('step 1: basics', () => {
    it('should enable Next button when name is entered', async () => {
      const { user } = render(<TrustProfileWizard />)

      const nameInput = screen.getByTestId('wizard.trustProfile.name')
      const nextButton = screen.getByTestId('wizard.trustProfile.next')

      expect(nextButton).toBeDisabled()

      await user.type(nameInput, 'Test Trust Profile')

      expect(nextButton).toBeEnabled()
    })

    it('should allow entering description', async () => {
      const { user } = render(<TrustProfileWizard />)

      const descInput = screen.getByTestId('wizard.trustProfile.description')
      await user.type(descInput, 'Test description for trust profile')

      expect(descInput).toHaveValue('Test description for trust profile')
    })

    it('should have framework type preselected to custom', () => {
      render(<TrustProfileWizard />)

      const frameworkSelect = screen.getByTestId('wizard.trustProfile.frameworkType')
      expect(frameworkSelect).toHaveTextContent(/custom/i)
    })

    it('should apply framework format presets and lock selection for non-custom frameworks', async () => {
      const { user } = render(<TrustProfileWizard />)

      const frameworkSelect = within(screen.getByTestId('wizard.trustProfile.frameworkTypeField')).getByRole('combobox')
      const jwtFormat = screen.getByTestId('wizard.trustProfile.format.jwt_vc')
      const sdJwtFormat = screen.getByTestId('wizard.trustProfile.format.sd_jwt_vc')
      const mdocFormat = screen.getByTestId('wizard.trustProfile.format.mdoc')
      const ldpFormat = screen.getByTestId('wizard.trustProfile.format.ldp_vc')

      expect(jwtFormat).toBeChecked()
      expect(sdJwtFormat).toBeChecked()
      expect(mdocFormat).toBeChecked()
      expect(ldpFormat).not.toBeChecked()

      fireEvent.mouseDown(frameworkSelect)
      await user.click(await screen.findByRole('option', { name: 'EUDI' }))

      await waitFor(() => {
        expect(jwtFormat).not.toBeChecked()
        expect(sdJwtFormat).toBeChecked()
        expect(mdocFormat).toBeChecked()
        expect(ldpFormat).not.toBeChecked()
      })

      expect(jwtFormat).toBeDisabled()
      expect(sdJwtFormat).toBeDisabled()
      expect(mdocFormat).toBeDisabled()
      expect(ldpFormat).toBeDisabled()
    })

    it('should not render supported formats as a required field', () => {
      render(<TrustProfileWizard />)

      expect(screen.getByRole('heading', { name: 'Supported Credential Formats' })).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: 'Supported Credential Formats *' })).not.toBeInTheDocument()
    })

    it('should keep Next enabled after selecting a locked framework preset', async () => {
      const { user } = render(<TrustProfileWizard />)

      const nameInput = screen.getByTestId('wizard.trustProfile.name')
      const nextButton = screen.getByTestId('wizard.trustProfile.next')

      await user.type(nameInput, 'EUDI Trust Profile')
      expect(nextButton).toBeEnabled()

      await selectFramework(user, 'EUDI')

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.format.sd_jwt_vc')).toBeChecked()
        expect(screen.getByTestId('wizard.trustProfile.format.mdoc')).toBeChecked()
      })

      expect(nextButton).toBeEnabled()
    })

    it('should allow free format selection again when switching back to custom', async () => {
      const { user } = render(<TrustProfileWizard />)

      const frameworkSelect = within(screen.getByTestId('wizard.trustProfile.frameworkTypeField')).getByRole('combobox')
      const jwtFormat = screen.getByTestId('wizard.trustProfile.format.jwt_vc')
      const ldpFormat = screen.getByTestId('wizard.trustProfile.format.ldp_vc')

      fireEvent.mouseDown(frameworkSelect)
      await user.click(await screen.findByRole('option', { name: 'AAMVA' }))

      await waitFor(() => {
        expect(jwtFormat).toBeDisabled()
        expect(ldpFormat).toBeDisabled()
      })

      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.frameworkTypeField')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: 'Custom' }))

      await waitFor(() => {
        expect(jwtFormat).not.toBeDisabled()
        expect(ldpFormat).not.toBeDisabled()
      })

      expect(jwtFormat).not.toBeChecked()
      await user.click(jwtFormat)
      await user.click(ldpFormat)

      expect(jwtFormat).toBeChecked()
      expect(ldpFormat).toBeChecked()
    })

    it('should validate name is required', async () => {
      const { user } = render(<TrustProfileWizard />)

      const nameInput = screen.getByTestId('wizard.trustProfile.name')
      const nextButton = screen.getByTestId('wizard.trustProfile.next')

      // Enter and then clear name
      await user.type(nameInput, 'Test')
      await user.clear(nameInput)

      expect(nextButton).toBeDisabled()
    })
  })

  describe('step navigation', () => {
    it('should navigate to step 2 when Next is clicked', async () => {
      const { user } = render(<TrustProfileWizard />)

      // Fill required field
      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Test Profile')

      // Click Next
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      // Should be on Trust Sources step
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.issuerDid')).toBeInTheDocument()
      })

      // Should show Back button
      expect(screen.getByTestId('wizard.trustProfile.back')).toBeInTheDocument()
    })

    it('should navigate back to step 1 from step 2', async () => {
      const { user } = render(<TrustProfileWizard />)

      // Go to step 2
      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Test Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.issuerDid')).toBeInTheDocument()
      })

      // Go back
      await user.click(screen.getByTestId('wizard.trustProfile.back'))

      // Should be back on Basics step
      await waitFor(() => {
        expect(screen.getByText('Basic Information')).toBeInTheDocument()
      })
    })

    it('should show Skip button on optional steps', async () => {
      const { user } = render(<TrustProfileWizard />)

      // Navigate to step 2
      await user.type(screen.getByLabelText(/Trust Profile Name/i), 'Test Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
    })

    it('should preserve data when navigating between steps', async () => {
      const { user } = render(<TrustProfileWizard />)

      const name = 'Test Trust Profile'

      // Enter data on step 1
      await user.type(screen.getByTestId('wizard.trustProfile.name'), name)

      // Go to step 2
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.issuerDid')).toBeInTheDocument()
      })

      // Go back to step 1
      await user.click(screen.getByTestId('wizard.trustProfile.back'))

      // Data should be preserved
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.name')).toHaveValue(name)
      })
    }, 20000)

    it('should navigate through all steps to review', async () => {
      const { user } = render(<TrustProfileWizard />)

      // Step 1: Basics
      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Test Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      // Step 2: Trust Sources (skip)
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      // Step 3: Cryptographic Policy (skip)
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      // Step 4: Review
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Review & Activate' })).toBeInTheDocument()
      })

      // Should show Create button
      expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
    })
  })

  describe('step 3: validation rules', () => {
    it('should apply framework algorithm presets and lock selection for non-custom frameworks', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'AAMVA Trust Profile')
      await selectFramework(user, 'AAMVA')
      await goToValidationRulesStep(user)

      const es256 = screen.getByTestId('wizard.trustProfile.algorithm.ES256')
      const es384 = screen.getByTestId('wizard.trustProfile.algorithm.ES384')
      const es512 = screen.getByTestId('wizard.trustProfile.algorithm.ES512')
      const eddsa = screen.getByTestId('wizard.trustProfile.algorithm.EdDSA')

      expect(es256).toBeChecked()
      expect(es384).toBeChecked()
      expect(es512).not.toBeChecked()
      expect(eddsa).not.toBeChecked()

      expect(es256).toBeDisabled()
      expect(es384).toBeDisabled()
      expect(es512).toBeDisabled()
      expect(eddsa).toBeDisabled()
    })

    it('should allow free algorithm selection again when switching back to custom', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Custom Trust Profile')
      await selectFramework(user, 'AAMVA')
      await selectFramework(user, 'Custom')
      await goToValidationRulesStep(user)

      const eddsa = screen.getByTestId('wizard.trustProfile.algorithm.EdDSA')
      const rs256 = screen.getByTestId('wizard.trustProfile.algorithm.RS256')

      expect(eddsa).not.toBeDisabled()
      expect(rs256).not.toBeDisabled()
      expect(eddsa).not.toBeChecked()
      expect(rs256).not.toBeChecked()

      await user.click(eddsa)
      await user.click(rs256)

      expect(eddsa).toBeChecked()
      expect(rs256).toBeChecked()
    })

    it('should show framework-locked banner and hide reset button when framework locks algorithms', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'AAMVA Trust Profile Banner')
      await selectFramework(user, 'AAMVA')
      await goToValidationRulesStep(user)

      expect(screen.getByText(/Signing algorithm selection is managed by the AAMVA framework/i)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Reset defaults' })).not.toBeInTheDocument()
    })

    it('should show defaults banner with reset button when Custom framework is selected', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Custom Trust Profile Banner')
      await goToValidationRulesStep(user)

      expect(screen.getByText('Secure defaults')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Reset defaults' })).toBeInTheDocument()
    })

    it('should submit with framework algorithm presets', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Submitted AAMVA Trust Profile')
      await selectFramework(user, 'AAMVA')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.issuerDid')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      expect(screen.getByTestId('wizard.trustProfile.algorithm.ES256')).toBeChecked()
      expect(screen.getByTestId('wizard.trustProfile.algorithm.ES384')).toBeChecked()
      expect(screen.getByTestId('wizard.trustProfile.algorithm.ES512')).not.toBeChecked()
      expect(screen.getByTestId('wizard.trustProfile.algorithm.EdDSA')).not.toBeChecked()

      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Review & Activate' })).toBeInTheDocument()
      })

      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.allowed_algorithms).toEqual(['ES256', 'ES384'])
      expect(lastTrustProfileRequestBody.validation_rules.allowed_algorithms).toEqual(['ES256', 'ES384'])
    })
  })

  describe('submission', () => {
    it('should trust an existing issuer identity from the managed issuer section', async () => {
      mockListIssuerProfiles.mockResolvedValue({
        profiles: [
          {
            id: 'issuer-profile-1',
            name: 'Existing managed issuer',
            issuer_did: 'did:web:issuer.example.com',
            signing_service_id: 'managed-openbao-transit',
            signing_key_reference: 'cred-issuer-test-es256',
            status: 'active',
          },
        ],
      })

      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Managed Identity Trust Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.existingIssuerProfile')).toBeInTheDocument()
      })

      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.existingIssuerProfile')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: /Existing managed issuer/i }))
      await user.click(screen.getByTestId('wizard.trustProfile.useIssuerProfile'))

      await waitFor(() => {
        expect(screen.getByText('1 trusted issuers')).toBeInTheDocument()
        expect(screen.getAllByText('did:web:issuer.example.com').length).toBeGreaterThan(0)
      })

      await user.click(screen.getByTestId('wizard.trustProfile.next'))
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.trust_sources).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            issuer_did: 'did:web:issuer.example.com',
            source_type: 'PINNED_ISSUER',
          }),
        ]),
      )
      expect(mockCreateIssuerProfile).not.toHaveBeenCalled()
    })

    it('should trust a ready KMS-derived DID identity even when no issuer profile exists yet', async () => {
      mockListIssuerProfiles.mockResolvedValue({ profiles: [] })

      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Derived DID Trust Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.existingIssuerProfile')).toBeInTheDocument()
      })

      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.existingIssuerProfile')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: /did:web:beta\.example\.com/i }))
      await user.click(screen.getByTestId('wizard.trustProfile.useIssuerProfile'))

      await waitFor(() => {
        expect(screen.getByText('1 trusted issuers')).toBeInTheDocument()
        expect(screen.getAllByText('did:web:beta.example.com').length).toBeGreaterThan(0)
      })

      await user.click(screen.getByTestId('wizard.trustProfile.next'))
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.trust_sources).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            issuer_did: 'did:web:beta.example.com',
            source_type: 'PINNED_ISSUER',
          }),
        ]),
      )
      expect(mockCreateIssuerProfile).not.toHaveBeenCalled()
    })

    it('should import a DID for an unbound signing key and trust it immediately', async () => {
      mockCreateIssuerProfile.mockResolvedValue({
        id: 'issuer-profile-imported',
        name: 'Imported key DID',
        issuer_did: 'did:web:imported.example.com',
        signing_service_id: 'managed-openbao-transit',
        signing_key_reference: 'cred-issuer-test-es256',
        status: 'active',
      })

      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Imported DID Trust Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.unboundSigningKey')).toBeInTheDocument()
      })

      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.unboundSigningKey')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: /Test issuer key/i }))

      await user.type(screen.getByTestId('wizard.trustProfile.importManagedDidValue'), 'did:web:imported.example.com')
      await user.click(screen.getByTestId('wizard.trustProfile.importManagedDid'))

      await waitFor(() => {
        expect(mockCreateIssuerProfile).toHaveBeenCalledWith(
          expect.objectContaining({
            issuer_did: 'did:web:imported.example.com',
            signing_service_id: 'managed-openbao-transit',
            signing_key_reference: 'cred-issuer-test-es256',
          }),
        )
      })

      await waitFor(() => {
        expect(screen.getByText('1 trusted issuers')).toBeInTheDocument()
        expect(screen.getAllByText('did:web:imported.example.com').length).toBeGreaterThan(0)
      })

      await user.click(screen.getByTestId('wizard.trustProfile.next'))
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.trust_sources).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            issuer_did: 'did:web:imported.example.com',
            source_type: 'PINNED_ISSUER',
          }),
        ]),
      )
    })

    it('should require trust sources before activating an empty trust profile', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Closed Trust Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.allowAllIssuers')).toBeInTheDocument()
      })

      expect(screen.getByTestId('wizard.trustProfile.allowAllIssuers')).not.toBeChecked()
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
        expect(screen.getAllByText(/set to activate immediately/i).length).toBeGreaterThan(0)
      })

      expect(screen.getByTestId('wizard.trustProfile.submit')).toBeDisabled()
      expect(lastTrustProfileRequestBody).toBeNull()

      await user.click(screen.getByRole('checkbox', { name: /activate immediately/i }))
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).not.toBeDisabled()
        expect(screen.getAllByText(/trust no issuers/i).length).toBeGreaterThan(0)
      })

      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.trust_sources).toEqual([])
      expect(lastTrustProfileRequestBody.allowed_issuers).toEqual([])
      expect(activatedTrustProfileId).toBeNull()
    })

    it('should allow opting into an empty trust profile that trusts any issuer', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Open Trust Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.allowAllIssuers')).toBeInTheDocument()
      })

      await user.click(screen.getByTestId('wizard.trustProfile.allowAllIssuers'))
      expect(screen.getByTestId('wizard.trustProfile.allowAllIssuers')).toBeChecked()
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
        expect(screen.getAllByText(/trust any issuer/i).length).toBeGreaterThan(0)
      })

      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.trust_sources).toEqual([])
      expect(lastTrustProfileRequestBody.allowed_issuers).toBeNull()
    })

    it('should submit wallet compatibility and runtime policy settings', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Runtime Aware Trust Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.issuerDid')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.issuanceProtocol')).toBeInTheDocument()
      })

      const walletAutocomplete = screen.getByTestId('wizard.trustProfile.supportedWallets')
      await user.type(walletAutocomplete, 'Acme')
      await user.click(await screen.findByText('Acme Wallet'))

      await user.click(screen.getByRole('button', { name: /show advanced options/i }))
      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.revocationStrategy')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: /temporary degradation/i }))
      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.clockSkew')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: '15 minutes' }))
      await user.click(screen.getByTestId('wizard.trustProfile.requireFreshness'))
      fireEvent.mouseDown(within(screen.getByTestId('wizard.trustProfile.freshnessWindow')).getByRole('combobox'))
      await user.click(await screen.findByRole('option', { name: '6 hours' }))

      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Review & Activate' })).toBeInTheDocument()
      })

      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      await waitFor(() => {
        expect(lastTrustProfileRequestBody).toBeTruthy()
      })

      expect(lastTrustProfileRequestBody.supported_wallet_ids).toEqual(['wallet-1'])
      expect(lastTrustProfileRequestBody.issuance_protocol).toBe('oid4vci')
      expect(lastTrustProfileRequestBody.revocation_policy).toEqual({ check_mode: 'SOFT_FAIL' })
      expect(lastTrustProfileRequestBody.time_policy).toEqual({
        clock_skew_seconds: 900,
        require_freshness: true,
        freshness_window_seconds: 21600,
      })
    })

    it('should submit successfully and show success message', async () => {
      const { user } = render(<TrustProfileWizard />)

      const profileName = 'Production Trust Profile'

      // Navigate through wizard
      await user.type(screen.getByTestId('wizard.trustProfile.name'), profileName)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      // Configure trusted issuer
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      // Submit
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
      })

      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      // Should show success message
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.success')).toBeInTheDocument()
      })

      const successScreen = screen.getByTestId('wizard.trustProfile.success')
      expect(within(successScreen).getByText('Trust Profile Created!')).toBeInTheDocument()
      expect(within(successScreen).getByText(new RegExp(profileName, 'i'))).toBeInTheDocument()
      expect(activatedTrustProfileId).toBe('trust-profile-1')

      // Should redirect after delay
      await waitFor(
        () => {
          expect(mockNavigate).toHaveBeenCalledWith('/console/org/templates/credentials')
        },
        { timeout: 2000 }
      )
    })

    it('should handle submission errors', async () => {
      const { user } = render(<TrustProfileWizard />)

      // Override API to return error
      server.use(
        http.post(`${MSW_BASE}/v1/trust-profiles`, () => {
          return HttpResponse.json(
            {
              error: {
                code: 'VALIDATION_ERROR',
                message: 'Trust profile name already exists',
              },
            },
            { status: 400 }
          )
        })
      )

      // Navigate through wizard
      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Duplicate Name')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      // Configure trusted issuer and continue to review
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      // Submit
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
      })

      await user.click(screen.getByTestId('wizard.trustProfile.submit'))

      // Should show error message
      await waitFor(() => {
        expect(screen.getByText(/already exists/i)).toBeInTheDocument()
      })

      // Should still be on review step
      expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
    })

    it('should show loading state during submission', async () => {
      const { user } = render(<TrustProfileWizard />)

      // Mock slow API response
      let resolveRequest: () => void
      const requestPromise = new Promise<void>((resolve) => {
        resolveRequest = resolve
      })

      server.use(
        http.post('https://beta.elevenidllc.com/v1/trust-profiles', async () => {
          await requestPromise
          return HttpResponse.json({ id: 'trust-profile-1', name: 'Test' }, { status: 201 })
        })
      )

      // Navigate to review
      await user.type(screen.getByTestId('wizard.trustProfile.name'), 'Test Profile')
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      // Submit
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument()
      })

      const submitButton = screen.getByTestId('wizard.trustProfile.submit')
      await user.click(submitButton)

      // Should show loading state (button disabled with "Creating..." text)
      await waitFor(() => {
        expect(submitButton).toBeDisabled()
        expect(submitButton).toHaveTextContent(/Submitting/i)
      })

      // Resolve request
      resolveRequest!()

      // Wait for completion
      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.success')).toBeInTheDocument()
      })
    })
  })

  describe('cancel', () => {
    it('should navigate away when Cancel is clicked', async () => {
      const { user } = render(<TrustProfileWizard />)

      await user.click(screen.getByTestId('wizard.trustProfile.cancel'))

      expect(mockNavigate).toHaveBeenCalledWith('/console/org/trust/profiles')
    })
  })

  describe('review step', () => {
    it('should display entered data in review step', async () => {
      const { user } = render(<TrustProfileWizard />)

      const profileName = 'My Trust Profile'
      const description = 'Test description'

      // Enter data
      await user.type(screen.getByTestId('wizard.trustProfile.name'), profileName)
      await user.type(screen.getByTestId('wizard.trustProfile.description'), description)

      // Navigate to review
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await addTrustedIssuer(user)
      await user.click(screen.getByTestId('wizard.trustProfile.next'))

      await waitFor(() => {
        expect(screen.getByTestId('wizard.trustProfile.skip')).toBeInTheDocument()
      })
      await user.click(screen.getByTestId('wizard.trustProfile.skip'))

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Review & Activate' })).toBeInTheDocument()
      })

      // Should show entered data
      await waitFor(() => {
        expect(screen.getByText(profileName)).toBeInTheDocument()
        expect(screen.getByText(description)).toBeInTheDocument()
      })
    }, 20000)
  })
})
