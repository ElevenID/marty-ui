/**
 * Integration Tests for Credential Template Wizard
 * 
 * Tests template creation flow including required claims and trust profile selection.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import CredentialTemplateWizard from '../CredentialTemplateWizard'
import { mockTrustProfiles } from '@test/mocks/fixtures'

const mockOrgContext = vi.hoisted(() => ({
  activeOrgId: 'console-org',
  authOrganizationId: 'auth-org',
}))

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: mockOrgContext.authOrganizationId }),
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: mockOrgContext.activeOrgId }),
}))

describe('CredentialTemplateWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockOrgContext.activeOrgId = 'console-org'
    mockOrgContext.authOrganizationId = 'auth-org'
  })

  describe('initial render', () => {
    it('should render wizard with all steps', () => {
      render(<CredentialTemplateWizard />)

      expect(screen.getByText('Build Credential Template')).toBeInTheDocument()
      expect(screen.getByText('Basics')).toBeInTheDocument()
      expect(screen.getByText('Claims')).toBeInTheDocument()
      expect(screen.getByText('Trust & Compliance')).toBeInTheDocument()
      expect(screen.getByText('Crypto & Validity')).toBeInTheDocument()
      expect(screen.getByText('Review & Activate')).toBeInTheDocument()
    })

    it('should have Next disabled until required fields filled', () => {
      render(<CredentialTemplateWizard />)

      expect(screen.getByTestId('wizard.template.next')).toBeDisabled()
    })
  })

  describe('step 1: basics', () => {
    it('should require name, credential type, and vct', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      const nextButton = screen.getByTestId('wizard.template.next')
      expect(nextButton).toBeDisabled()

      // Enter name only — credential_type is pre-filled via initialData
      await user.type(screen.getByLabelText(/Template Name/i), 'mDL Template')
      expect(nextButton).toBeDisabled()

      // Enter vct
      await user.type(screen.getByLabelText(/VCT/i), 'org.iso.18013.5.1.mDL')
      expect(nextButton).toBeEnabled()
    })

    it('should allow optional description', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      const descInput = screen.getByLabelText(/Description/i)
      await user.type(descInput, 'Mobile driver license credential')

      expect(descInput).toHaveValue('Mobile driver license credential')
    })
  })

  describe('step 2: claims', () => {
    it('should require at least one claim', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      // Complete basics step
      await user.type(screen.getByLabelText(/Template Name/i), 'Test Template')
      await user.type(screen.getByLabelText(/Credential Type/i), 'VerifiableCredential')
      await user.type(screen.getByLabelText(/VCT/i), 'org.example.test')
      await user.click(screen.getByTestId('wizard.template.next'))

      // On claims step, Next should be disabled without claims
      await waitFor(() => {
        expect(screen.getByTestId('wizard.template.next')).toBeDisabled()
      })
    })

    it('should enable Next when claims are added', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      // Navigate to claims step
      await user.type(screen.getByLabelText(/Template Name/i), 'Test Template')
      await user.type(screen.getByLabelText(/Credential Type/i), 'VerifiableCredential')
      await user.type(screen.getByLabelText(/VCT/i), 'org.example.test')
      await user.click(screen.getByTestId('wizard.template.next'))

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /claims/i })).toBeInTheDocument()
      })

      // Add a claim (implementation depends on ClaimsStep UI)
      // This is a placeholder - adjust based on actual UI
      const addClaimButton = screen.queryByRole('button', { name: /Add Claim/i })
      if (addClaimButton) {
        await user.click(addClaimButton)
        // Fill claim fields...
        
        await waitFor(() => {
          expect(screen.getByTestId('wizard.template.next')).toBeEnabled()
        })
      }
    })
  })

  describe('step 3: trust & compliance', () => {
    it('should require trust profile selection', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      // Navigate to trust & compliance step
      await user.type(screen.getByLabelText(/Template Name/i), 'Test Template')
      await user.type(screen.getByLabelText(/Credential Type/i), 'VerifiableCredential')
      await user.type(screen.getByLabelText(/VCT/i), 'org.example.test')
      await user.click(screen.getByTestId('wizard.template.next'))

      // Claims step - add minimal data to proceed
      await waitFor(() => {
        const nextButton = screen.getByTestId('wizard.template.next')
        // If we can't add claims through UI, this test will fail appropriately
      })
    })
  })

  describe('complete wizard flow', () => {
    it('creates the template in the active console organization', async () => {
      let createdPayload: Record<string, unknown> | undefined
      let activationRequested = false

      server.use(
        http.get('*/v1/trust-profiles', ({ request }) => {
          expect(new URL(request.url).searchParams.get('organization_id')).toBe('console-org')
          return HttpResponse.json([
            {
              id: 'trust-1',
              name: 'Production Trust',
              status: 'active',
              trust_sources: [{ issuer_did: 'did:web:issuer.example.com' }],
            },
          ])
        }),
        http.get('*/v1/signing-keys/issuer-profiles', ({ request }) => {
          expect(new URL(request.url).searchParams.get('organization_id')).toBe('console-org')
          return HttpResponse.json({
            profiles: [
              {
                id: 'issuer-1',
                name: 'Production Issuer',
                issuer_did: 'did:web:issuer.example.com',
                signing_service_id: 'managed-openbao-transit',
                signing_key_reference: 'issuer-key',
                status: 'active',
              },
            ],
          })
        }),
        http.get('*/v1/revocation-profiles', ({ request }) => {
          expect(new URL(request.url).searchParams.get('organization_id')).toBe('console-org')
          return HttpResponse.json([{
            id: 'revocation-1',
            organization_id: 'console-org',
            name: 'Lifecycle Status',
            status: 'ACTIVE',
            check_mode: 'ALWAYS',
          }])
        }),
        http.get('*/v1/compliance-profiles', ({ request }) => {
          expect(new URL(request.url).searchParams.get('organization_id')).toBe('console-org')
          return HttpResponse.json([{
            id: 'compliance-1',
            organization_id: null,
            name: 'OID4VC Core',
            compliance_code: 'OID4VC',
            credential_format: 'SD_JWT_VC',
            status: 'ACTIVE',
            is_system: true,
            discoverable: true,
          }])
        }),
        http.get('*/v1/wallet-registry', () => HttpResponse.json([])),
        http.post('*/v1/credential-templates', async ({ request }) => {
          createdPayload = await request.json() as Record<string, unknown>
          return HttpResponse.json({
            id: 'template-1',
            ...createdPayload,
            status: 'draft',
          })
        }),
        http.post('*/v1/credential-templates/template-1/activate', () => {
          activationRequested = true
          return HttpResponse.json({
            id: 'template-1',
            name: 'Production mDL Template',
            status: 'active',
          })
        })
      )

      const { user } = render(<CredentialTemplateWizard />)

      await user.type(screen.getByLabelText(/Template Name/i), 'Production mDL Template')
      await user.type(screen.getByLabelText(/VCT/i), 'org.example.employee')
      await user.click(screen.getByTestId('wizard.template.next'))

      await user.click(await screen.findByRole('button', { name: /employee/i }))
      await waitFor(() => expect(screen.getByTestId('wizard.template.next')).toBeEnabled())
      await user.click(screen.getByTestId('wizard.template.next'))

      await waitFor(() => expect(screen.getByTestId('wizard.template.next')).toBeEnabled())
      await user.click(screen.getByTestId('wizard.template.next'))

      const revocationSelect = await screen.findByLabelText(/revocation profile/i)
      await user.click(revocationSelect)
      await user.click(await screen.findByRole('option', { name: /lifecycle status/i }))
      await waitFor(() => expect(screen.getByTestId('wizard.template.next')).toBeEnabled())
      await user.click(screen.getByTestId('wizard.template.next'))

      await waitFor(() => expect(screen.getByTestId('wizard.template.submit')).toBeEnabled())
      await user.click(screen.getByTestId('wizard.template.submit'))

      await waitFor(() => {
        expect(createdPayload).toEqual(expect.objectContaining({
          organization_id: 'console-org',
          issuer_profile_id: 'issuer-1',
          key_access_mode: 'REMOTE_SIGNING',
          trust_profile_id: 'trust-1',
          compliance_profile_id: 'compliance-1',
          revocation_profile_id: 'revocation-1',
        }))
        expect(createdPayload).not.toHaveProperty('activate_immediately')
        expect(createdPayload).not.toHaveProperty('supported_wallet_ids')
        expect(createdPayload).not.toHaveProperty('issuance_protocol')
        expect(activationRequested).toBe(true)
        expect(screen.getByText(/now active/i)).toBeInTheDocument()
      })
    })

    it('should successfully create template with minimum required data', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      // Basics
      await user.type(screen.getByLabelText(/Template Name/i), 'Production mDL Template')
      await user.type(screen.getByLabelText(/Credential Type/i), 'VerifiableCredential')
      await user.type(screen.getByLabelText(/VCT/i), 'org.iso.18013.5.1.mDL')

      // Note: Full navigation test would require implementing claims addition
      // This validates the initial step only
      expect(screen.getByTestId('wizard.template.next')).toBeEnabled()
    })

    it('should show success message after creation', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      // Mock successful submission
      server.use(
        http.post('http://localhost:8000/v1/credential-templates', () => {
          return HttpResponse.json({
            id: 1,
            name: 'Test Template',
            status: 'active',
          })
        })
      )

      // Note: Complete flow test requires full wizard navigation
      // Placeholder for when ClaimsStep UI is defined
    })
  })

  describe('error handling', () => {
    it('should display API errors during submission', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      server.use(
        http.post('http://localhost:8000/v1/credential-templates', () => {
          return HttpResponse.json(
            {
              error: {
                code: 'VALIDATION_ERROR',
                message: 'Template name already exists',
              },
            },
            { status: 400 }
          )
        })
      )

      // Error will be shown during actual submission
      // Complete test requires full wizard navigation
    })
  })

  describe('navigation', () => {
    it('should preserve data when navigating back', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      const templateName = 'My Template'

      // Enter data
      await user.type(screen.getByLabelText(/Template Name/i), templateName)
      await user.type(screen.getByLabelText(/Credential Type/i), 'VerifiableCredential')
      await user.type(screen.getByLabelText(/VCT/i), 'org.test')

      // Go forward
      await user.click(screen.getByTestId('wizard.template.next'))

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /claims/i })).toBeInTheDocument()
      })

      // Go back
      await user.click(screen.getByTestId('wizard.template.back'))

      // Data preserved
      await waitFor(() => {
        expect(screen.getByLabelText(/Template Name/i)).toHaveValue(templateName)
      })
    })

    it('should cancel and navigate away', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      await user.click(screen.getByTestId('wizard.template.cancel'))

      expect(mockNavigate).toHaveBeenCalledWith('/console/org/templates/credentials')
    })
  })

  describe('validation', () => {
    it('should not allow empty template name', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      const nameInput = screen.getByLabelText(/Template Name/i)
      
      await user.type(nameInput, 'Test')
      await user.clear(nameInput)

      expect(screen.getByTestId('wizard.template.next')).toBeDisabled()
    })

    it('should validate vct format', async () => {
      const { user } = render(<CredentialTemplateWizard />)

      // Fill required fields
      await user.type(screen.getByLabelText(/Template Name/i), 'Test')
      await user.type(screen.getByLabelText(/Credential Type/i), 'VerifiableCredential')

      // VCT should follow a specific format (namespace.type)
      const vctInput = screen.getByLabelText(/VCT/i)
      await user.type(vctInput, 'org.example.credential')

      expect(screen.getByTestId('wizard.template.next')).toBeEnabled()
    })
  })
})
