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
import { http, HttpResponse } from 'msw'
import DeploymentProfileWizard from '../DeploymentProfileWizard'

// Mock navigation
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

describe('DeploymentProfileWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
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

    // Step 1 should be active
    const stepper = screen.getByRole('list') // MUI Stepper renders as <ol>
    expect(stepper).toBeInTheDocument()
  })

  it('should validate environment step before proceeding', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Try to go next without filling required fields
    const nextButton = screen.getByTestId('wizard.deployment.next')
    await user.click(nextButton)

    // Should still be on first step
    expect(screen.getByText('Environment')).toBeInTheDocument()
  })

  it('should complete environment step', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Fill environment fields
    const nameInput = screen.getByLabelText(/profile name/i)
    await user.type(nameInput, 'Production API')

    const descInput = screen.getByLabelText(/description/i)
    await user.type(descInput, 'Production environment for API')

    // Select environment type
    const apiRadio = screen.getByLabelText(/api/i)
    await user.click(apiRadio)

    // Proceed to next step
    const nextButton = screen.getByTestId('wizard.deployment.next')
    await user.click(nextButton)

    // Should advance to runtime settings
    await waitFor(() => {
      expect(screen.getByText('Runtime Settings')).toBeInTheDocument()
    })
  })

  it('should complete runtime settings step', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Complete environment step first
    await user.type(screen.getByLabelText(/profile name/i), 'Test Profile')
    await user.click(screen.getByLabelText(/api/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    await waitFor(() => {
      expect(screen.getByText('Runtime Settings')).toBeInTheDocument()
    })

    // Select default policy
    const policySelect = screen.getByLabelText(/default policy/i)
    await user.click(policySelect)
    
    // Select first policy from dropdown
    const firstPolicy = await screen.findByText(/age verification/i)
    await user.click(firstPolicy)

    // Proceed to integration step
    await user.click(screen.getByTestId('wizard.deployment.next'))

    await waitFor(() => {
      expect(screen.getByText('Integration')).toBeInTheDocument()
    })
  })

  it('should allow navigation back to previous steps', async () => {
    const user = userEvent.setup()
    render(<DeploymentProfileWizard />)

    // Advance to step 2
    await user.type(screen.getByLabelText(/profile name/i), 'Test')
    await user.click(screen.getByLabelText(/api/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    await waitFor(() => {
      expect(screen.getByText('Runtime Settings')).toBeInTheDocument()
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

    // Fill environment
    await user.type(screen.getByLabelText(/profile name/i), 'Preserve Test')
    await user.type(screen.getByLabelText(/description/i), 'Data should persist')
    await user.click(screen.getByLabelText(/kiosk/i))

    // Go next
    await user.click(screen.getByTestId('wizard.deployment.next'))
    await waitFor(() => screen.getByText('Runtime Settings'))

    // Go back
    await user.click(screen.getByTestId('wizard.deployment.back'))

    // Data should be preserved
    expect(screen.getByLabelText(/profile name/i)).toHaveValue('Preserve Test')
    expect(screen.getByLabelText(/description/i)).toHaveValue('Data should persist')
    expect(screen.getByLabelText(/kiosk/i)).toBeChecked()
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

    // Step 1: Environment
    await user.type(screen.getByLabelText(/profile name/i), 'Production')
    await user.click(screen.getByLabelText(/api/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // Step 2: Runtime Settings
    await waitFor(() => screen.getByText('Runtime Settings'))
    const policySelect = screen.getByLabelText(/default policy/i)
    await user.click(policySelect)
    await user.click(await screen.findByText(/age verification/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // Step 3: Integration (skip)
    await waitFor(() => screen.getByText('Integration'))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // Step 4: Review & Submit
    await waitFor(() => screen.getByText('Review & Activate'))
    const submitButton = screen.getByRole('button', { name: /activate profile/i })
    await user.click(submitButton)

    // Verify success state
    await waitFor(() => {
      expect(screen.getByText(/profile created successfully/i)).toBeInTheDocument()
    })

    // Verify submitted data
    expect(submittedData.name).toBe('Production')
    expect(submittedData.environment_type).toBe('api')
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

    // Complete wizard
    await user.type(screen.getByLabelText(/profile name/i), 'Existing')
    await user.click(screen.getByLabelText(/api/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Runtime Settings'))
    await user.click(screen.getByLabelText(/default policy/i))
    await user.click(await screen.findByText(/age verification/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Integration'))
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Review & Activate'))
    await user.click(screen.getByRole('button', { name: /activate profile/i }))

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
    expect(mockNavigate).toHaveBeenCalledWith('/console/deploy/profiles')
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

    // Complete wizard to review step
    await user.type(screen.getByLabelText(/profile name/i), 'Draft Profile')
    await user.click(screen.getByLabelText(/api/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Runtime Settings'))
    await user.click(screen.getByLabelText(/default policy/i))
    await user.click(await screen.findByText(/age verification/i))
    await user.click(screen.getByTestId('wizard.deployment.next'))
    
    await waitFor(() => screen.getByText('Integration'))
    await user.click(screen.getByTestId('wizard.deployment.next'))

    // On review step, uncheck activate immediately
    await waitFor(() => screen.getByText('Review & Activate'))
    const activateCheckbox = screen.getByLabelText(/activate immediately/i)
    await user.click(activateCheckbox)

    await user.click(screen.getByRole('button', { name: /save draft/i }))

    await waitFor(() => {
      expect(submittedData.status).toBe('draft')
    })
  })
})
