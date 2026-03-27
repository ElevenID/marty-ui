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
import { render, screen, waitFor, within } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import TrustProfileWizard from '../TrustProfileWizard'

const TRANSLATIONS = {
  'wizards.trustProfile.title': 'Build Trust Profile',
  'wizards.trustProfile.description': 'Create a trust profile for credential verification.',
  'wizards.trustProfile.steps.basics': 'Basics',
  'wizards.trustProfile.steps.trustSources': 'Trust Sources',
  'wizards.trustProfile.steps.validationRules': 'Validation Rules',
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
  'wizards.trustProfile.basicsStep.fields.supportedFormats': 'Supported Formats',
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
  'wizards.trustProfile.trustSourcesStep.infoAlert.skippingDescription': 'You can come back before submission.',
  'wizards.trustProfile.trustSourcesStep.examplesTitle': 'Example DIDs',
  'wizards.trustProfile.trustSourcesStep.issuerDid.label': 'Issuer DID',
  'wizards.trustProfile.trustSourcesStep.issuerDid.placeholder': 'did:web:issuer.example.com',
  'wizards.trustProfile.trustSourcesStep.issuerDid.helper': 'Enter one DID per issuer.',
  'wizards.trustProfile.trustSourcesStep.addButton': 'Add',
  'wizards.trustProfile.trustSourcesStep.trustedIssuersTitle': '{{count}} trusted issuers',
  'wizards.trustProfile.trustSourcesStep.emptyState': 'No issuers added yet.',
  'wizards.trustProfile.trustSourcesStep.comingSoon.title': 'Coming soon.',
  'wizards.trustProfile.trustSourcesStep.comingSoon.description': 'Registry import will land later.',
  'wizards.trustProfile.validationRulesStep.title': 'Validation Rules',
  'wizards.trustProfile.validationRulesStep.optionalChip': 'Optional',
  'wizards.trustProfile.validationRulesStep.description': 'Fine-tune validation requirements.',
  'wizards.trustProfile.validationRulesStep.defaultsAlert.title': 'Secure defaults',
  'wizards.trustProfile.validationRulesStep.defaultsAlert.description': 'Default settings are suitable for most deployments.',
  'wizards.trustProfile.validationRulesStep.resetDefaults': 'Reset defaults',
  'wizards.trustProfile.validationRulesStep.allowedAlgorithms.title': 'Allowed Algorithms',
  'wizards.trustProfile.validationRulesStep.allowedAlgorithms.helper': 'Select accepted algorithms.',
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
  'wizards.trustProfile.reviewStep.sections.validationRules': 'Validation Rules',
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
  'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfigured': 'No trusted issuers configured',
  'wizards.trustProfile.reviewStep.activationExplanation.title': 'Activation',
  'wizards.trustProfile.reviewStep.activationExplanation.description': 'Choose whether to activate immediately.',
  'wizards.trustProfile.reviewStep.activateImmediately.label': 'Activate immediately',
  'wizards.trustProfile.reviewStep.activateImmediately.description': 'Enable this trust profile after creation.',
  'wizards.trustProfile.reviewStep.trustSourcesRequired': 'Add at least one trusted issuer before creating this trust profile.',
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
  beforeEach(() => {
    vi.clearAllMocks()
    server.use(
      http.post('https://beta.elevenidllc.com/v1/trust-profiles', async ({ request }) => {
        const body = await request.json() as any
        return HttpResponse.json({
          id: 'trust-profile-1',
          status: 'active',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
          ...body,
        }, { status: 201 })
      }),
      http.post('https://beta.elevenidllc.com/v1/trust-profiles/:id/issuers', async ({ request, params }) => {
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

  describe('initial render', () => {
    it('should render wizard with correct initial state', () => {
      render(<TrustProfileWizard />)

      // Check title
      expect(screen.getByText('Build Trust Profile')).toBeInTheDocument()

      // Check stepper shows all steps
      expect(screen.getByText('Basics')).toBeInTheDocument()
      expect(screen.getByText('Trust Sources')).toBeInTheDocument()
      expect(screen.getByText('Validation Rules')).toBeInTheDocument()
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

      // Step 3: Validation Rules (skip)
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

  describe('submission', () => {
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
        http.post('https://beta.elevenidllc.com/v1/trust-profiles', () => {
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
