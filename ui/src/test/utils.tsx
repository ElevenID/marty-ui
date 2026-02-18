/**
 * Test Utilities
 * 
 * Reusable test helpers for component testing:
 * - Custom render with Router and Theme providers
 * - Wait utilities
 * - User event helpers
 */

import { ReactElement } from 'react'
import { render as rtlRender, RenderOptions } from '@testing-library/react'
import { BrowserRouter, MemoryRouter } from 'react-router-dom'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import userEvent from '@testing-library/user-event'

// Create default MUI theme for tests
const theme = createTheme()

interface WrapperProps {
  children: React.ReactNode
}

/**
 * Custom render that wraps components with necessary providers
 */
function customRender(
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) {
  function Wrapper({ children }: WrapperProps) {
    return (
      <BrowserRouter>
        <ThemeProvider theme={theme}>
          {children}
        </ThemeProvider>
      </BrowserRouter>
    )
  }

  return {
    user: userEvent.setup(),
    ...rtlRender(ui, { wrapper: Wrapper, ...options }),
  }
}

/**
 * Custom render with initial router entries (for testing specific routes)
 */
export function renderWithRouter(
  ui: ReactElement,
  {
    initialEntries = ['/'],
    ...renderOptions
  }: RenderOptions & { initialEntries?: string[] } = {}
) {
  const Wrapper = ({ children }: WrapperProps) => {
    return (
      <MemoryRouter initialEntries={initialEntries}>
        <ThemeProvider theme={theme}>
          {children}
        </ThemeProvider>
      </MemoryRouter>
    )
  }

  return {
    user: userEvent.setup(),
    ...rtlRender(ui, { wrapper: Wrapper, ...renderOptions }),
  }
}

/**
 * Wait for an element to be removed from the DOM
 */
export { waitFor, waitForElementToBeRemoved } from '@testing-library/react'

/**
 * Create a mock user for testing
 */
export function createMockUser(overrides = {}) {
  return {
    id: 1,
    username: 'test@example.com',
    email: 'test@example.com',
    capabilities: {
      'admin:platform': true,
      apply: true,
    },
    organizations: [],
    default_experience: 'applicant',
    first_name: 'Test',
    last_name: 'User',
    is_active: true,
    ...overrides,
  }
}

/**
 * Create mock wizard data
 */
export function createMockWizardData(step: number, data = {}) {
  return {
    activeStep: step,
    data,
    loading: false,
    error: null,
    success: false,
  }
}

// Re-export everything from @testing-library/react
export * from '@testing-library/react'

// Export custom render as default render
export { customRender as render }

/**
 * Render without router (for tests that need custom routing)
 */
export function renderWithoutRouter(
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) {
  function Wrapper({ children }: WrapperProps) {
    return (
      <ThemeProvider theme={theme}>
        {children}
      </ThemeProvider>
    )
  }

  return {
    user: userEvent.setup(),
    ...rtlRender(ui, { wrapper: Wrapper, ...options }),
  }
}
