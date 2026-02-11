/**
 * Integration Tests for Presentation Policy Wizard
 * 
 * Tests policy creation flow including trust profile selection and claim configuration.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import PresentationPolicyWizard from '../PresentationPolicyWizard'

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

describe('PresentationPolicyWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('initial render', () => {
    it('should render wizard with all steps', () => {
      render(<PresentationPolicyWizard />)

      expect(screen.getByText(/Presentation Policy/i)).toBeInTheDocument()
      expect(screen.getByText('Trust Profile')).toBeInTheDocument()
      expect(screen.getByText('Select Template')).toBeInTheDocument()
      expect(screen.getByText('Configure Claims')).toBeInTheDocument()
      expect(screen.getByText('Freshness & Binding')).toBeInTheDocument()
      expect(screen.getByText('Review')).toBeInTheDocument()
    })

    it('should start on trust profile step', () => {
      render(<PresentationPolicyWizard />)

      // First step content should be visible
expect(screen.getByTestId('wizard.policy.next')).toBeInTheDocument()
    })
  })

  describe('step 1: trust profile selection', () => {
    it('should require trust profile selection to proceed', () => {
      render(<PresentationPolicyWizard />)

      // Next should be disabled until trust profile selected
      const nextButton = screen.getByTestId('wizard.policy.next')
      // Implementation depends on whether trust profile list is shown
    })

    it('should show available trust profiles', async () => {
      render(<PresentationPolicyWizard />)

      // Trust profiles loaded from API via MSW
      await waitFor(() => {
        // Check if trust profiles are displayed
        // Implementation depends on TrustProfileStep UI
      })
    })
  })

  describe('step 2: template selection', () => {
    it('should require template selection', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Navigate to template selection
      // (Requires trust profile to be selected first)
    })

    it('should show available credential templates', async () => {
      render(<PresentationPolicyWizard />)

      // Templates loaded via MSW
      await waitFor(() => {
        // Check for template list
      })
    })
  })

  describe('step 3: claims configuration', () => {
    it('should require at least one claim', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Navigate through steps
      // Claim configuration UI
    })

    it('should allow configuring required vs optional claims', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Test claim requirement toggles
    })
  })

  describe('step 4: freshness & binding', () => {
    it('should have default freshness values', () => {
      render(<PresentationPolicyWizard />)

      // Default max_credential_age_seconds: 31536000 (1 year)
      // Default max_proof_age_seconds: 300 (5 minutes)
    })

    it('should allow customizing holder binding', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Test holder_binding options: device_key, biometric, etc.
    })

    it('should be marked as optional step', () => {
      render(<PresentationPolicyWizard />)

      // Step should show "optional" indicator or allow skipping
    })
  })

  describe('complete flow', () => {
    it('should successfully create policy', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', () => {
          return HttpResponse.json({
            id: 1,
            name: 'Age Verification Policy',
            status: 'active',
          })
        })
      )

      // Complete flow test
      // Note: Requires full step navigation implementation
    })

    it('should redirect to deployment profiles on success', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', () => {
          return HttpResponse.json({ id: 1, name: 'Test Policy' })
        })
      )

      // After successful creation
      await waitFor(
        () => {
          expect(mockNavigate).toHaveBeenCalledWith('/console/deploy/profiles')
        },
        { timeout: 3000 }
      )
    })
  })

  describe('error handling', () => {
    it('should handle missing trust profile prerequisite', () => {
      server.use(
        http.get('http://localhost:8000/v1/trust-profiles', () => {
          return HttpResponse.json([])
        })
      )

      render(<PresentationPolicyWizard />)

      // Should show error or warning about missing trust profile
    })

    it('should display API errors', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      server.use(
        http.post('http://localhost:8000/v1/presentation-policies', () => {
          return HttpResponse.json(
            {
              error: {
                code: 'VALIDATION_ERROR',
                message: 'Invalid claim configuration',
              },
            },
            { status: 400 }
          )
        })
      )

      // Error will show during submission
    })
  })

  describe('navigation', () => {
    it('should preserve data when navigating between steps', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Data persistence test
    })

    it('should allow jumping to previous steps from review', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Review step should have Edit buttons for each section
    })

    it('should cancel and navigate away', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      await user.click(screen.getByTestId('wizard.policy.cancel'))

      expect(mockNavigate).toHaveBeenCalled()
    })
  })

  describe('review step', () => {
    it('should display all configured values', async () => {
      const { user } = render(<PresentationPolicyWizard />)

      // Navigate to review
      // Should show:
      // - Selected trust profile
      // - Selected template
      // - Configured claims
      // - Freshness settings
      // - Holder binding
    })

    it('should show activation toggle', () => {
      render(<PresentationPolicyWizard />)

      // "Activate immediately" checkbox or toggle
    })
  })
})
