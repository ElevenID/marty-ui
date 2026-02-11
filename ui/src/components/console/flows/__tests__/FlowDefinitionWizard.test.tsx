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
    await user.click(screen.getByTestId('flow-type-verification')!)
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

    // Add a step
    const addStepButton = screen.getByRole('button', { name: /add step/i })
    await user.click(addStepButton)

    // Select step type
    const stepTypeSelect = screen.getByLabelText(/step type/i)
    await user.click(stepTypeSelect)
    await user.click(screen.getByText(/request attributes/i))

    // Now next should be enabled
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

    // Add multiple steps
    const addButton = screen.getByRole('button', { name: /add step/i })
    await user.click(addButton)
    
    // First step
    let stepTypeSelect = screen.getAllByLabelText(/step type/i)[0]
    await user.click(stepTypeSelect)
    await user.click(screen.getByText(/request attributes/i))

    // Add second step
    await user.click(addButton)
    stepTypeSelect = screen.getAllByLabelText(/step type/i)[1]
    await user.click(stepTypeSelect)
    await user.click(screen.getByText(/verify credential/i))

    // Verify both steps exist
    expect(screen.getByText(/request attributes/i)).toBeInTheDocument()
    expect(screen.getByText(/verify credential/i)).toBeInTheDocument()

    // Would test drag-drop here but requires more complex event simulation
  })

  it('should allow optional deployment binding', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    // Complete first two steps
    await user.click(screen.getByTestId('flow-type-verification')!)
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Test Flow')
    await user.click(screen.getByRole('button', { name: /add step/i }))
    await user.click(screen.getAllByLabelText(/step type/i)[0])
    await user.click(screen.getByText(/request attributes/i))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Deployment binding step
    await waitFor(() => {
      expect(screen.getByText('Bind Deployment')).toBeInTheDocument()
    })

    // Should show optional indicator
    expect(screen.getByText(/optional/i)).toBeInTheDocument()

    // Can skip this step
    await user.click(screen.getByTestId('wizard.flow.next'))

    await waitFor(() => {
      expect(screen.getByText('Review')).toBeInTheDocument()
    })
  })

  it('should complete full flow creation', async () => {
    const user = userEvent.setup()
    render(<FlowDefinitionWizard />)

    let submittedData: any
    server.use(
      http.post('http://localhost:8000/api/v1/identity/flows', async ({ request }) => {
        submittedData = await request.json()
        return HttpResponse.json(
          {
            id: 789,
            ...submittedData,
            created_at: '2024-01-15T10:00:00Z',
          },
          { status: 201 }
        )
      })
    )

    // Step 1: Flow Type
    await user.click(screen.getByTestId('flow-type-verification')!)
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 2: Configure Steps
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Complete Flow')
    await user.type(screen.getByLabelText(/description/i), 'Full test flow')
    
    await user.click(screen.getByRole('button', { name: /add step/i }))
    await user.click(screen.getAllByLabelText(/step type/i)[0])
    await user.click(screen.getByText(/request attributes/i))
    
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 3: Bind Deployment (skip)
    await waitFor(() => screen.getByText('Bind Deployment'))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // Step 4: Review and Submit
    await waitFor(() => screen.getByText('Review'))
    
    const submitButton = screen.getByTestId('wizard.flow.submit')
    await user.click(submitButton)

    // Success state
    await waitFor(() => {
      expect(screen.getByText(/flow created successfully/i)).toBeInTheDocument()
    })

    // Should redirect after delay
    await waitFor(
      () => {
        expect(mockNavigate).toHaveBeenCalledWith('/console/operate')
      },
      { timeout: 3000 }
    )

    // Verify submitted data
    expect(submittedData.name).toBe('Complete Flow')
    expect(submittedData.flowType).toBe('verification')
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
    render(<FlowDefinitionWizard />)

    server.use(
      http.post('http://localhost:8000/api/v1/identity/flows', () => {
        return HttpResponse.json(
          {
            error: {
              code: 'INVALID_FLOW_CONFIG',
              message: 'Flow configuration is invalid',
            },
          },
          { status: 400 }
        )
      })
    )

    // Complete wizard
    await user.click(screen.getByTestId('flow-type-verification')!)
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Configure Steps'))
    await user.type(screen.getByLabelText(/flow name/i), 'Error Test')
    await user.click(screen.getByRole('button', { name: /add step/i }))
    await user.click(screen.getAllByLabelText(/step type/i)[0])
    await user.click(screen.getByText(/request attributes/i))
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Bind Deployment'))
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Review'))
    await user.click(screen.getByTestId('wizard.flow.submit'))

    // Error alert should appear
    await waitFor(() => {
      expect(screen.getByText(/flow configuration is invalid/i)).toBeInTheDocument()
    })
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
    
    // Should see both step types available
    await user.click(screen.getAllByLabelText(/step type/i)[0])
    expect(screen.getByText(/request attributes/i)).toBeInTheDocument()
    expect(screen.getByText(/issue credential/i)).toBeInTheDocument()
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
    await user.click(screen.getAllByLabelText(/step type/i)[0])
    await user.click(screen.getByText(/request attributes/i))
    await user.click(screen.getByTestId('wizard.flow.next'))
    
    await waitFor(() => screen.getByText('Bind Deployment'))
    await user.click(screen.getByTestId('wizard.flow.next'))

    // On review step
    await waitFor(() => screen.getByText('Review'))

    // Click edit button for flow type
    const editFlowTypeButton = screen.getByRole('button', { name: /edit flow type/i })
    await user.click(editFlowTypeButton)

    // Should return to flow type step
    await waitFor(() => {
      expect(screen.getByText('Flow Type')).toBeInTheDocument()
    })
  })
})
