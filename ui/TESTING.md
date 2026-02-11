# marty-ui Testing Infrastructure

This document describes the testing infrastructure for the marty-ui frontend application.

## Overview

The testing strategy follows a **testing pyramid** approach:

- **~70% Component/Integration Tests** - Fast, DOM-level tests using React Testing Library + Vitest
- **~20% API Contract Tests** - Validate UI against stable API shapes using MSW
- **~10% E2E Smoke Tests** - Critical user flows using Playwright

## Tech Stack

- **Test Runner**: [Vitest](https://vitest.dev/) - Fast, Vite-native test runner
- **Component Testing**: [React Testing Library](https://testing-library.com/react) - User-centric component tests
- **API Mocking**: [MSW](https://mswjs.io/) (Mock Service Worker) - Network-level API mocking
- **E2E Testing**: [Playwright](https://playwright.dev/) - Browser automation for smoke tests
- **Visual Regression**: [Storybook](https://storybook.js.org/) + Playwright screenshots

## Project Structure

```
ui/
├── src/
│   ├── components/
│   │   └── __tests__/           # Component tests
│   ├── config/
│   │   └── __tests__/           # Pure function tests
│   ├── hooks/
│   │   └── __tests__/           # Hook tests
│   ├── services/
│   │   └── __tests__/           # API service tests
│   └── test/
│       ├── setup.ts             # Vitest setup file
│       ├── utils.tsx            # Test utilities & custom render
│       └── mocks/
│           ├── fixtures.ts      # Mock data scenarios
│           ├── handlers.ts      # MSW request handlers
│           ├── server.ts        # MSW server (Node.js)
│           └── browser.ts       # MSW worker (browser)
├── .storybook/                  # Storybook configuration
├── vitest.config.ts             # Vitest configuration
└── package.json                 # Test scripts
```

## Running Tests

### Unit & Integration Tests

```bash
# Run all tests once
npm test

# Watch mode (re-run on file changes)
npm run test:watch

# Generate coverage report
npm run test:coverage

# Open Vitest UI (interactive test explorer)
npm run test:ui
```

### E2E Tests

```bash
# Run E2E smoke tests
cd ../tests
npx playwright test
```

### Storybook

```bash
# Start Storybook dev server
npm run storybook

# Build static Storybook
npm run storybook:build

# Run visual regression tests
npm run test:visual
```

## Writing Tests

### Component Tests

Use the custom `render` function from `@test/utils` which provides router and theme context:

```typescript
import { render, screen, waitFor } from '@test/utils'
import { MyComponent } from './MyComponent'

describe('MyComponent', () => {
  it('should render successfully', () => {
    const { user } = render(<MyComponent />)
    
    expect(screen.getByText('Hello World')).toBeInTheDocument()
  })
  
  it('should handle user interaction', async () => {
    const { user } = render(<MyComponent />)
    
    await user.click(screen.getByRole('button', { name: 'Submit' }))
    
    await waitFor(() => {
      expect(screen.getByText('Success')).toBeInTheDocument()
    })
  })
})
```

### Hook Tests

Use `renderHook` from React Testing Library:

```typescript
import { renderHook, act } from '@testing-library/react'
import { useMyHook } from './useMyHook'

describe('useMyHook', () => {
  it('should update state', () => {
    const { result } = renderHook(() => useMyHook())
    
    act(() => {
      result.current.updateValue('new value')
    })
    
    expect(result.current.value).toBe('new value')
  })
})
```

### API Service Tests

Use MSW to mock API responses:

```typescript
import { describe, it, expect } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import { getTrustProfiles } from './trustProfileApi'

describe('trustProfileApi', () => {
  it('should fetch trust profiles', async () => {
    // MSW already mocks this by default (see handlers.ts)
    const profiles = await getTrustProfiles()
    
    expect(profiles).toHaveLength(1)
    expect(profiles[0].status).toBe('active')
  })
  
  it('should handle errors', async () => {
    // Override default handler for this test
    server.use(
      http.get('/v1/trust-profiles', () => {
        return HttpResponse.json(
          { error: { message: 'Server error' } },
          { status: 500 }
        )
      })
    )
    
    await expect(getTrustProfiles()).rejects.toThrow('Server error')
  })
})
```

### Testing with Different Data Scenarios

Use scenario-specific handlers from `@test/mocks/handlers`:

```typescript
import { render, screen } from '@test/utils'
import { server } from '@test/mocks/server'
import { emptyOrgHandlers } from '@test/mocks/handlers'
import { Dashboard } from './Dashboard'

describe('Dashboard', () => {
  it('should show empty state', async () => {
    // Use empty org scenario
    server.use(...emptyOrgHandlers)
    
    render(<Dashboard />)
    
    await screen.findByText('No Trust Profiles configured')
  })
})
```

## Mock Data Scenarios

The following pre-configured scenarios are available in `@test/mocks/fixtures`:

- **`dashboardScenarios.empty`** - No resources configured
- **`dashboardScenarios.partiallyConfigured`** - Trust profile exists, template has issues
- **`dashboardScenarios.fullyReady`** - All resources configured and ready
- **`mockErrors`** - Various error responses (401, 403, 404, 500)

## Coverage Thresholds

Coverage targets are configured in `vitest.config.ts`:

- **Lines**: 70%
- **Functions**: 70%
- **Branches**: 70%
- **Statements**: 70%

These are enforced in CI. Use `npm run test:coverage` to check current coverage.

## Best Practices

### 1. Test User Behavior, Not Implementation

❌ **Don't test implementation details:**
```typescript
expect(component.state.isLoading).toBe(true)
```

✅ **Do test from user perspective:**
```typescript
expect(screen.getByText('Loading...')).toBeInTheDocument()
```

### 2. Use Semantic Queries

Prefer queries in this order:
1. `getByRole` - Most accessible
2. `getByLabelText` - Forms
3. `getByPlaceholderText` - Form inputs
4. `getByText` - Non-interactive content
5. `getByTestId` - Last resort only

### 3. Wait for Async Changes

❌ **Don't use arbitrary delays:**
```typescript
await new Promise(resolve => setTimeout(resolve, 1000))
```

✅ **Do wait for specific conditions:**
```typescript
await waitFor(() => {
  expect(screen.getByText('Success')).toBeInTheDocument()
})
```

### 4. Clean Up After Tests

Cleanup is automatic via `afterEach(cleanup)` in `setup.ts`, but for manual cleanup:

```typescript
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
  server.resetHandlers()
})
```

### 5. Isolate Tests

Each test should be independent and not rely on other tests' state:

```typescript
describe('MyComponent', () => {
  beforeEach(() => {
    // Reset to known state before each test
  })
  
  it('test 1', () => { /* ... */ })
  it('test 2', () => { /* ... */ })
})
```

## Debugging Tests

### Vitest UI

```bash
npm run test:ui
```

Opens an interactive UI in your browser showing test results, coverage, and allowing you to filter/re-run tests.

### Debug Single Test

Add `.only` to focus on one test:

```typescript
it.only('should debug this test', () => {
  // Only this test will run
})
```

### Print DOM State

```typescript
import { screen } from '@test/utils'

// Print current DOM
screen.debug()

// Print specific element
screen.debug(screen.getByRole('button'))
```

### VS Code Debugging

1. Set breakpoint in test file
2. Run "Debug Test" from test file
3. Or use "JavaScript Debug Terminal"

## CI Integration

Tests run automatically on:
- **Pull Requests** - Unit/integration tests + lint
- **Main branch** - All tests + coverage report
- **Nightly** - E2E smoke tests + visual regression

## Common Issues

### MSW Warnings

If you see "unhandled request" warnings, add handlers to `handlers.ts` or mark them as expected:

```typescript
server.listen({ onUnhandledRequest: 'warn' })
```

### Material-UI Warnings

If you see MUI console errors, ensure components are wrapped with `ThemeProvider` (handled by custom `render`).

### React Router Errors

If you see router errors, use `render` from `@test/utils` which provides `BrowserRouter` automatically.

## Next Steps

Planned additions:
- [ ] Wizard integration tests (Trust Profile, Template, Policy wizards)
- [ ] Dashboard component integration tests
- [ ] Table/list component tests with filtering
- [ ] Visual regression test suite via Playwright + Storybook
- [ ] API contract validation with Zod schemas

## Resources

- [Vitest Documentation](https://vitest.dev/)
- [React Testing Library Docs](https://testing-library.com/react)
- [MSW Documentation](https://mswjs.io/)
- [Playwright Documentation](https://playwright.dev/)
- [Testing Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)
