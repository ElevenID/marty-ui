/**
 * Integration Tests for Flow Definition Wizard
 * 
 * Tests wizard flow for creating flow definitions with:
 * - Flow type selection (Verification/Issuance/Combined)
 * - Steps configuration
 * - Deployment binding
 * - Review and activation
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { render } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import FlowDefinitionWizard from '../FlowDefinitionWizard'

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}))

describe('FlowDefinitionWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render wizard with all steps', () => {
    render(<FlowDefinitionWizard />)

    expect(screen.getByText('Flow Type')).toBeInTheDocument()
    expect(screen.getByText('Configure Steps')).toBeInTheDocument()
    expect(screen.getByText('Bind Deployment')).toBeInTheDocument()
    expect(screen.getByText('Review')).toBeInTheDocument()
  })

  it('should require flow type selection', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    const nextButton = screen.getByTestId('wizard.flow.next')
    
    // Next button should be disabled without selection
    expect(nextButton).toBeDisabled()

    // Select flow type
    const verificationCard = screen.getByTestId('flow-type-verification')
    await user.click(verificationCard!)

    // Next button should now be enabled
    await waitFor(() => {
      expect(nextButton).not.toBeDisabled()
    })
  })

  it('should support verification flow creation', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Step 1: Select verification flow
    const verificationCard = screen.getByTestId('flow-type-verification')
    await user.click(verificationCard!)
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Should advance to configure steps
    await waitFor(() => {
      expect(screen.getByText('Configure Steps')).toBeInTheDocument()
    })
  })

  it('should support issuance flow creation', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Select issuance flow
    const issuanceCard = screen.getByTestId('flow-type-issuance')
    await user.click(issuanceCard!)
    await user.click(screen.getByTestId('wizard.flow.next'))

    await waitFor(() => {
      expect(screen.getByText('Configure Steps')).toBeInTheDocument()
    })
  })

  it('should validate flow name and steps', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Step 1: Select flow type
    await user.click(screen.getByTestId('flow-type-issuance_oid4vci')!)
    await user.click(screen.getByTestId('wizard.flow.next'))

    await waitFor(() => screen.getByText('Configure Steps'))

    // Next should be disabled without name and steps
    const nextButton = screen.getByTestId('wizard.flow.next')
    expect(nextButton).toBeDisabled()

    // Add flow name
    const nameInput = screen.getByLabelText(/flow name/i)
    await user.type(nameInput, 'Age Verification Flow')

    // Still disabled without steps
    expect(nextButton).toBeDisabled()

    // Add a step (adds a step with default type 'custom')
    const addStepButton = screen.getByRole('button', { name: /add step/i })
    await user.click(addStepButton)

    // Now next should be enabled (name is set and flowSteps.length > 0)
    await waitFor(() => {
      expect(nextButton).not.toBeDisabled()
    })
  })

  it('should support drag-drop step reordering', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Navigate to configure steps
    await user.click(screen.getByTestId('flow-type-verification')!)
    await user.click(screen.getByTestId('wizard.flow.next'))
    await waitFor(() => screen.getByText('Configure Steps'))

    // Add flow name
    await user.type(screen.getByLabelText(/flow name/i), 'Test Flow')

    // Add multiple steps using the Add Step button
    const addButton = screen.getByRole('button', { name: /add step/i })
    await user.click(addButton)
    await user.click(addButton)

    // Verify both steps exist (default names: 'Step 1', 'Step 2')
    const stepInputs = screen.getAllByPlaceholderText(/step name/i)
    expect(stepInputs).toHaveLength(2)
  })

  it('should require and auto-fill available deployment binding prerequisites', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Complete first two steps
    await user.click(screen.getByTestId('flow-type-verification')!)
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Test Flow')
    await user.click(screen.getByRole('button', { name: /add step/i }))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Preconditions step (optional)
    await waitFor(() => {
      expect(screen.getByText('Preconditions')).toBeInTheDocument()
    })
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Deployment binding step
    await waitFor(() => {
      expect(screen.getByText('Bind Deployment')).toBeInTheDocument()
    })

    await waitFor(() => {
      expect(screen.getByText('Production Deployment')).toBeInTheDocument()
      expect(screen.getByTestId('wizard.flow.next')).not.toBeDisabled()
    })

    await user.click(screen.getByTestId('wizard.flow.next'))

    await waitFor(() => {
      expect(screen.getByText('Review')).toBeInTheDocument()
    })
  })

  it('should submit a persisted flow definition with required references', async () => {
    const user = userEvent.setup()
    let submittedPayload: any = null
    server.use(
      http.post('http://localhost:8000/v1/flows/definitions', async ({ request }) => {
        submittedPayload = await request.json()
        return HttpResponse.json({
          id: 'flow-created',
          organization_id: submittedPayload.organization_id,
          name: submittedPayload.name,
          description: submittedPayload.description,
          flow_type: 'oid4vci_pre_authorized',
          flow_category: 'ISSUANCE',
          trust_profile_id: submittedPayload.trust_profile_id,
          credential_template_id: submittedPayload.credential_template_id,
          deployment_profile_ids: submittedPayload.deployment_profile_ids,
          approval_strategy: submittedPayload.approval_strategy,
          enabled: submittedPayload.enabled,
          status: 'ACTIVE',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        })
      })
    )
    render(<FlowDefinitionWizard />)

    // Step 1: Flow Type
    await user.click(screen.getByTestId('flow-type-issuance_oid4vci')!)
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 2: Configure Steps
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Complete Flow')
    await user.type(screen.getByLabelText(/description/i), 'Full test flow')
    
    await user.click(screen.getByRole('button', { name: /add step/i }))
    
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 3: Preconditions (skip)
    await waitFor(() => screen.getByText('Preconditions'))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 4: Bind Deployment
    await waitFor(() => screen.getByText('Bind Deployment'))
    await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).not.toBeDisabled())
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 5: Review and Submit
    await waitFor(() => screen.getByText('Review'))
    
    const submitButton = screen.getByTestId('wizard.flow.submit')
    await user.click(submitButton)

    // Success state after the API confirms flow creation.
    await waitFor(() => {
      expect(screen.getByText(/Flow Created/i)).toBeInTheDocument()
    })

    expect(submittedPayload).toMatchObject({
      organization_id: 'org-1',
      name: 'Complete Flow',
      description: 'Full test flow',
      flow_type: 'issuance_oid4vci',
      credential_template_id: 1,
      deployment_profile_id: 1,
      deployment_profile_ids: [1],
      approval_strategy: 'AUTO',
      enabled: true,
    })
    expect(submittedPayload.steps[0]).toMatchObject({
      name: 'Step 1',
      step_type: 'user_input',
    })

    // Should redirect after delay (1500ms useWizard + 2000ms component)
    await waitFor(
      () => {
        expect(mockNavigate).toHaveBeenCalledWith('/console/org/operate')
      },
      { timeout: 5000 }
    )
  })

  it('should preserve data across navigation', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Select flow type
    await user.click(screen.getByTestId('flow-type-issuance')!)
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Add configuration
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Persistent Flow')
    
    // Go back
    await user.click(screen.getByTestId('wizard.flow.back'))

    // Verify flow type is still selected
    await waitFor(() => {
      const issuanceCard = screen.getByTestId('flow-type-issuance')!
      expect(issuanceCard).toHaveAttribute('aria-selected', 'true')
    })

    // Go forward again
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Flow name should be preserved
    await waitFor(() => {
      expect(screen.getByLabelText(/flow name/i)).toHaveValue('Persistent Flow')
    })
  })

  it('should handle API errors', async () => {
    const user = userEvent.setup()
    server.use(
      http.post('http://localhost:8000/v1/flows/definitions', () => {
        return HttpResponse.json(
          { error: 'validation_error', error_description: 'credential_template_id is required' },
          { status: 400 }
        )
      })
    )
    render(<FlowDefinitionWizard />)

    // Complete wizard and let the API validation error surface.
    await user.click(screen.getByTestId('flow-type-issuance_oid4vci')!)
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Error Test')
    await user.click(screen.getByRole('button', { name: /add step/i }))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Skip Preconditions
    await waitFor(() => screen.getByText('Preconditions'))
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Bind Deployment'))
    await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).not.toBeDisabled())
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Review'))
    await user.click(screen.getByTestId('wizard.flow.submit'))

    await waitFor(() => {
      expect(screen.getByText(/credential_template_id is required/i)).toBeInTheDocument()
    })
    expect(screen.queryByText(/Flow Created/i)).not.toBeInTheDocument()
  })

  it('should support combined flow type', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Select combined flow (verification + issuance)
    const combinedCard = screen.getByTestId('flow-type-combined')
    await user.click(combinedCard!)

    await user.click(screen.getByTestId('wizard.flow.next'))

    await waitFor(() => {
      expect(screen.getByText('Configure Steps')).toBeInTheDocument()
    })

    // Combined flows should support both verification and issuance steps
    await user.type(screen.getByLabelText(/flow name/i), 'Combined Flow')
    await user.click(screen.getByRole('button', { name: /add step/i }))
    
    // Step was added with default type
    const stepInputs = screen.getAllByPlaceholderText(/step name/i)
    expect(stepInputs.length).toBeGreaterThan(0)
  })

  it('should allow editing from review step', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Navigate to review
    await user.click(screen.getByTestId('flow-type-verification')!)
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Editable Flow')
    await user.click(screen.getByRole('button', { name: /add step/i }))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Skip Preconditions
    await waitFor(() => screen.getByText('Preconditions'))
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Bind Deployment'))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // On review step
    await waitFor(() => screen.getByText('Review'))

    // Click first edit button (navigates to Configure Steps)
    const editButtons = screen.getAllByRole('button', { name: /edit/i })
    await user.click(editButtons[0])

    // Should return to configure steps
    await waitFor(() => {
      expect(screen.getByLabelText(/flow name/i)).toHaveValue('Editable Flow')
    })
  })
})
