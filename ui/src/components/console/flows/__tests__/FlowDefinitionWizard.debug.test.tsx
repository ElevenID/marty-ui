import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BrowserRouter } from 'react-router-dom'
import FlowDefinitionWizard from '../FlowDefinitionWizard'

describe('FlowDefinitionWizard Debug', () => {
  beforeEach(() => {
    // Reset any mocks if needed
  })

  it('should enable Next button when flow type selected', async () => {
    const user = userEvent.setup()
    
    render(
      <BrowserRouter>
        <FlowDefinitionWizard />
      </BrowserRouter>
    )

    // Get initial button state
    const nextButton = screen.getByTestId('wizard.flow.next')
    console.log('Initial button disabled:', nextButton.hasAttribute('disabled'))
    
    // Get the verification card
    const verificationCard = screen.getByTestId('flow-type-verification')
    console.log('Found verification card:', verificationCard !== null)
    
    // Click the card
    await user.click(verificationCard)
    console.log('Clicked verification card')
    
    // Wait a bit for state updates
    await new Promise(resolve => setTimeout(resolve, 100))
    
    // Check button state after click
    console.log('Button disabled after click:', nextButton.hasAttribute('disabled'))
    
    // Check aria-selected state of card
    const cardActionArea = verificationCard.querySelector('[role="button"]')
    console.log('Card aria-selected:', cardActionArea?.getAttribute('aria-selected'))
    
    // Wait for button to be enabled
    await waitFor(() => {
      const isDisabled = nextButton.hasAttribute('disabled')
      console.log('Waiting... button disabled:', isDisabled)
      expect(nextButton).not.toBeDisabled()
    }, { timeout: 3000, interval: 100 })
  })
})
