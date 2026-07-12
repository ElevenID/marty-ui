/**
 * Integration Tests for Deployment Profile Wizard
 * 
 * Tests wizard flow for creating deployment profiles that bind
 * identity logic to runtime environments (API, Kiosk, Mobile).
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { render } from '@test/utils'
import { server } from '@test/mocks/server'
import { mockPolicies } from '@test/mocks/fixtures'
import { http, HttpResponse } from 'msw'
import DeploymentProfileWizard from '../DeploymentProfileWizard'

const PRESENTATION_POLICIES_URL = 'http://localhost:8000/v1/presentation-policies'

const goToRuntimeSettings = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.type(screen.getByLabelText(/profile name/i), 'Test Profile')
  await user.click(screen.getByTestId('wizard.deployment.next'))
}

// Mock navigation
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}))

describe('DeploymentProfileWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    server.use(
      http.get(PRESENTATION_POLICIES_URL, () => {
        return HttpResponse.json([mockPolicies.valid])
      })
    )
  })

  it('should render wizard with all steps', () => {
    render(<DeploymentProfileWizard />)

    expect(screen.getByText('Environment')).toBeInTheDocument()
    expect(screen.getByText('Runtime Settings')).toBeInTheDocument()
    expect(screen.getByText('Integration')).toBeInTheDocument()
    expect(screen.getByText('Review & Activate')).toBeInTheDocument()
  })

  it('should start at environment step', () => {
    render(<DeploymentProfileWizard />)

    // Step 1 should display environment configuration
    expect(screen.getByText(/Environment Configuration/i)).toBeInTheDocument()
  })

  it('should validate environment step before proceeding', async () => {
    render(<DeploymentProfileWizard />)

    // Next is disabled without filling required fields
    const nextButton = screen.getByTestId('wizard.deployment.next')
    expect(nextButton).toBeDisabled()

    // Should still be on first step
    expect(screen.getByText('Environment')).toBeInTheDocument()
  })

  it('should complete environment step', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Fill environment fields (environment_type is pre-filled as 'api')
    const nameInput = screen.getByLabelText(/profile name/i)
    await user.type(nameInput, 'Production API')

    const descInput = screen.getByLabelText(/description/i)
    await user.type(descInput, 'Production environment for API')

    // Proceed to next step
    const nextButton = screen.getByTestId('wizard.deployment.next')
    await user.click(nextButton)

    // Should advance to runtime settings
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Runtime Settings/i })).toBeInTheDocument()
    })
  })

  it('should complete runtime settings step', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Complete environment step first (environment_type pre-filled as 'api')
    await user.type(screen.getByLabelText(/profile name/i), 'Test Profile')
    await user.click(screen.getByTestId('wizard.deployment.next'))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Runtime Settings/i })).toBeInTheDocument()
    })

    // Wait for policies to load and auto-select (only one policy exists)
    await waitFor(() => {
      expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled()
    })

    // Proceed to integration step
    await user.click(screen.getByTestId('wizard.deployment.next'))

    await waitFor(() => {
      expect(screen.getByText('Integration')).toBeInTheDocument()
    })
  })

  it.each([
    ['a direct array with uppercase status', [mockPolicies.valid]],
    ['a direct array with lowercase status', [{ ...mockPolicies.valid, status: 'active' }]],
    ['a direct array with an active flag', [{ ...mockPolicies.valid, status: 'DRAFT', is_active: true }]],
    ['a direct array with padded uppercase status', [{ ...mockPolicies.valid, status: ' ACTIVE ' }]],
  ])('should auto-select the sole active policy from %s', async (_label, responseBody) => {
    const user = userEvent.setup()
    server.use(
      http.get(PRESENTATION_POLICIES_URL, () => HttpResponse.json(responseBody))
    )
    render(<DeploymentProfileWizard />)

    await goToRuntimeSettings(user)

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Runtime Settings/i })).toBeInTheDocument()
      expect(screen.getByTestId('deployment-default-policy-select')).toHaveTextContent('Age Verification')
      expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled()
    })
  })

  it('should exclude inactive policies and route to policy creation', async () => {
    const user = userEvent.setup()
    server.use(
      http.get(PRESENTATION_POLICIES_URL, () => HttpResponse.json([
        { ...mockPolicies.valid, id: 2, status: 'DRAFT' },
        { ...mockPolicies.valid, id: 3, status: 'ARCHIVED' },
        { ...mockPolicies.valid, id: 4, status: null, is_active: false },
      ]))
    )
    render(<DeploymentProfileWizard />)

    await goToRuntimeSettings(user)

    expect(await screen.findByRole('heading', { name: /Presentation Policy Required/i })).toBeInTheDocument()
    expect(screen.getByTestId('wizard.deployment.next')).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /Create Presentation Policy/i }))
    expect(mockNavigate).toHaveBeenCalledWith('/console/org/policies/presentation/new')
  })

  it('should fail closed for an empty direct array', async () => {
    const user = userEvent.setup()
    server.use(http.get(PRESENTATION_POLICIES_URL, () => HttpResponse.json([])))
    render(<DeploymentProfileWizard />)

    await goToRuntimeSettings(user)

    expect(await screen.findByRole('heading', { name: /Presentation Policy Required/i })).toBeInTheDocument()
    expect(screen.getByTestId('wizard.deployment.next')).toBeDisabled()
  })

  it.each([
    ['a null response', null],
    ['an empty object', {}],
    ['an unsupported response envelope', { data: { results: [mockPolicies.valid] } }],
  ])('should expose a recoverable contract error for %s', async (_label, responseBody) => {
    const user = userEvent.setup()
    server.use(
      http.get(PRESENTATION_POLICIES_URL, () => HttpResponse.json(responseBody))
    )
    render(<DeploymentProfileWizard />)

    await goToRuntimeSettings(user)

    expect(await screen.findByRole('alert')).toHaveTextContent(/malformed list response/i)
    expect(screen.getByRole('button', { name: /Refresh/i })).toBeInTheDocument()
    expect(screen.getByTestId('wizard.deployment.next')).toBeDisabled()
  })

  it('should retry a failed policy request', async () => {
    const user = userEvent.setup()
    let shouldFail = true
    let requestCount = 0
    server.use(
      http.get(PRESENTATION_POLICIES_URL, () => {
        requestCount += 1
        if (shouldFail) {
          return HttpResponse.json(
            { error: { message: 'Presentation policies are temporarily unavailable' } },
            { status: 400 }
          )
        }
        return HttpResponse.json([mockPolicies.valid])
      })
    )
    render(<DeploymentProfileWizard />)

    await goToRuntimeSettings(user)

    expect(await screen.findByRole('alert')).toHaveTextContent('Presentation policies are temporarily unavailable')
    expect(screen.getByTestId('wizard.deployment.next')).toBeDisabled()

    shouldFail = false
    await user.click(screen.getByRole('button', { name: /Refresh/i }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Runtime Settings/i })).toBeInTheDocument()
      expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled()
    })
    expect(requestCount).toBe(2)
  })

  it('should retry after an unsupported policy response', async () => {
    const user = userEvent.setup()
    let responseBody: unknown = { data: { results: [mockPolicies.valid] } }
    server.use(
      http.get(PRESENTATION_POLICIES_URL, () => HttpResponse.json(responseBody))
    )
    render(<DeploymentProfileWizard />)

    await goToRuntimeSettings(user)

    expect(await screen.findByRole('alert')).toHaveTextContent(/malformed list response/i)
    responseBody = [mockPolicies.valid]
    await user.click(screen.getByRole('button', { name: /Refresh/i }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Runtime Settings/i })).toBeInTheDocument()
      expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled()
    })
  })

  it('should allow navigation back to previous steps', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Advance to step 2 (environment_type pre-filled as 'api')
    await user.type(screen.getByLabelText(/profile name/i), 'Test')
    await user.click(screen.getByTestId('wizard.deployment.next'))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Runtime Settings/i })).toBeInTheDocument()
    })

    // Go back
    const backButton = screen.getByTestId('wizard.deployment.back')
    await user.click(backButton)

    // Should return to environment step
    await waitFor(() => {
      expect(screen.getByLabelText(/profile name/i)).toHaveValue('Test')
    })
  })

  it('should preserve data when navigating between steps', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Fill environment (switch to kiosk via card click)
    await user.type(screen.getByLabelText(/profile name/i), 'Preserve Test')
    await user.type(screen.getByLabelText(/description/i), 'Data should persist')
    await user.click(screen.getByTestId('env-type-kiosk'))

    // Go next
    await user.click(screen.getByTestId('wizard.deployment.next'))
    await waitFor(() => screen.getByRole('heading', { name: /Runtime Settings/i }))

    // Go back
    await user.click(screen.getByTestId('wizard.deployment.back'))

    // Data should be preserved
    expect(screen.getByLabelText(/profile name/i)).toHaveValue('Preserve Test')
    expect(screen.getByLabelText(/description/i)).toHaveValue('Data should persist')
  })

  it('should submit deployment profile', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    let submittedData: any
    server.use(
      http.post('http://localhost:8000/v1/deployment-profiles', async ({ request }) => {
        submittedData = await request.json()
        return HttpResponse.json(
          {
            id: 123,
            ...submittedData,
            created_at: '2024-01-15T10:00:00Z',
          },
          { status: 201 }
        )
      })
    )

    // Step 1: Environment (environment_type pre-filled as 'api')
    await user.type(screen.getByLabelText(/profile name/i), 'Production')
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // Step 2: Runtime Settings (policy auto-selected - only one active policy)
    await waitFor(() => screen.getByRole('heading', { name: /Runtime Settings/i }))
    await waitFor(() => expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled())
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // Step 3: Integration (skip)
    await waitFor(() => screen.getByText('Integration'))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // Step 4: Review & Submit
    await waitFor(() => screen.getByRole('heading', { name: /Review & Activate/i }))
    expect(screen.queryByText(/Generate API key automatically/i)).not.toBeInTheDocument()
    await user.click(screen.getByTestId('wizard.deployment.submit'))

    // Verify success state
    await waitFor(() => {
      expect(screen.getByText(/Deployment Profile Created Successfully/i)).toBeInTheDocument()
    })
    expect(screen.queryByText(/API key has been generated/i)).not.toBeInTheDocument()

    // Verify submitted data
    expect(submittedData.name).toBe('Production')
    expect(submittedData.environment_type).toBe('api')
    expect(submittedData.default_policy_id).toBe(1)
    expect(submittedData.presentation_policy_ids).toEqual([1])
    expect(submittedData.trust_profile_id).toBe('trust-1')
    expect(submittedData.status).toBe('active')
    expect(submittedData.activate_immediately).toBe(true)
  })

  it('should handle API errors', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    server.use(
      http.post('http://localhost:8000/v1/deployment-profiles', () => {
        return HttpResponse.json(
          {
            error: {
              code: 'DUPLICATE_NAME',
              message: 'A profile with this name already exists',
            },
          },
          { status: 409 }
        )
      })
    )

    // Complete wizard (environment_type pre-filled as 'api')
    await user.type(screen.getByLabelText(/profile name/i), 'Existing')
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByRole('heading', { name: /Runtime Settings/i }))
    await waitFor(() => expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled())
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Integration'))
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByRole('heading', { name: /Review & Activate/i }))
    await user.click(screen.getByTestId('wizard.deployment.submit'))

    // Error should be displayed
    await waitFor(() => {
      expect(screen.getByText(/profile with this name already exists/i)).toBeInTheDocument()
    })
  })

  it('should support cancel action', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    const cancelButton = screen.getByTestId('wizard.deployment.cancel')
    await user.click(cancelButton)

    // Should navigate back to profiles list
    expect(mockNavigate).toHaveBeenCalledWith('/console/org/deploy/profiles')
  })

  it('should allow draft mode creation', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    let submittedData: any
    server.use(
      http.post('http://localhost:8000/v1/deployment-profiles', async ({ request }) => {
        submittedData = await request.json()
        return HttpResponse.json({ id: 456, ...submittedData }, { status: 201 })
      })
    )

    // Complete wizard to review step (environment_type pre-filled as 'api')
    await user.type(screen.getByLabelText(/profile name/i), 'Draft Profile')
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    // Step 2: Runtime Settings (policy auto-selected - only one active policy)
    await waitFor(() => screen.getByRole('heading', { name: /Runtime Settings/i }))
    await waitFor(() => expect(screen.getByTestId('wizard.deployment.next')).not.toBeDisabled())
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Integration'))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // On review step, uncheck activate immediately
    await waitFor(() => screen.getByRole('heading', { name: /Review & Activate/i }))
    const activateCheckbox = screen.getByLabelText(/activate immediately/i)
    await user.click(activateCheckbox)

    await user.click(screen.getByTestId('wizard.deployment.submit'))

    await waitFor(() => {
      expect(submittedData.status).toBe('draft')
      expect(submittedData.activate_immediately).toBe(false)
    })
  })
})
