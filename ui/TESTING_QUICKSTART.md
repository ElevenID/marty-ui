# Testing Quick Start Guide

Get started writing tests for marty-ui in 5 minutes.

## Setup (One-Time)

```bash
cd ui
npm install
```

## Run Tests

```bash
npm test              # Run once
npm run test:watch   # Watch mode (recommended for TDD)
npm run test:ui      # Interactive browser UI
```

## Write Your First Test

### 1. Component Test

Create `MyComponent.test.tsx` next to your component:

```typescript
import { render, screen } from '@test/utils'
import { MyComponent } from './MyComponent'

describe('MyComponent', () => {
  it('should render', () => {
    render(<MyComponent title="Hello" />)
    
    expect(screen.getByText('Hello')).toBeInTheDocument()
  })
  
  it('should handle click', async () => {
    const { user } = render(<MyComponent />)
    
    await user.click(screen.getByRole('button', { name: 'Submit' }))
    
    expect(screen.getByText('Success')).toBeInTheDocument()
  })
})
```

### 2. Hook Test

Create `useMyHook.test.ts`:

```typescript
import { renderHook, act } from '@testing-library/react'
import { useMyHook } from './useMyHook'

describe('useMyHook', () => {
  it('should manage state', () => {
    const { result } = renderHook(() => useMyHook())
    
    act(() => {
      result.current.setValue('test')
    })
    
    expect(result.current.value).toBe('test')
  })
})
```

### 3. API Service Test

Create `myApi.test.ts`:

```typescript
import { describe, it, expect } from 'vitest'
import { getItems } from './myApi'

describe('myApi', () => {
  it('should fetch items', async () => {
    // MSW mocks the API automatically (see src/test/mocks/handlers.ts)
    const items = await getItems()
    
    expect(items).toHaveLength(1)
  })
})
```

## Common Patterns

### Wait for Async Updates

```typescript
import { waitFor } from '@test/utils'

await waitFor(() => {
  expect(screen.getByText('Loaded')).toBeInTheDocument()
})
```

### Mock API Responses

```typescript
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'

describe('MyComponent', () => {
  it('should handle errors', async () => {
    server.use(
      http.get('/v1/items', () => {
        return HttpResponse.json(
          { error: { message: 'Failed' } },
          { status: 500 }
        )
      })
    )
    
    render(<MyComponent />)
    
    await screen.findByText('Failed')
  })
})
```

### Test User Interactions

```typescript
const { user } = render(<Form />)

// Type in input
await user.type(screen.getByLabelText('Name'), 'John')

// Click button
await user.click(screen.getByRole('button', { name: 'Submit' }))

// Select from dropdown
await user.selectOptions(screen.getByLabelText('Country'), 'USA')
```

### Query Priorities (in order)

1. `getByRole('button', { name: 'Submit' })` - Best for accessibility
2. `getByLabelText('Email')` - Forms
3. `getByPlaceholderText('Enter email')` - Inputs
4. `getByText('Hello')` - Content
5. `getByTestId('custom-id')` - Last resort

## Debug Tests

### Print DOM

```typescript
import { screen } from '@test/utils'

screen.debug() // Print entire DOM
screen.debug(screen.getByRole('button')) // Print specific element
```

### Focus on One Test

```typescript
it.only('should debug this', () => {
  // Only this test runs
})

describe.skip('MyComponent', () => {
  // Skip entire suite
})
```

### Visual Debugging with Vitest UI

```bash
npm run test:ui
```

Opens browser UI showing:
- Test results and coverage
- Source code with highlighting
- Console output
- Re-run individual tests

## Pre-Configured Scenarios

Use these in your tests:

```typescript
import { 
  dashboardScenarios,
  mockUsers,
  mockTrustProfiles,
  mockErrors 
} from '@test/mocks/fixtures'

// Empty org
const data = dashboardScenarios.empty

// Admin user
const admin = mockUsers.admin

// Simulate error
server.use(
  http.get('/v1/items', () => {
    return HttpResponse.json(mockErrors.serverError, { status: 500 })
  })
)
```

## Storybook

```bash
npm run storybook  # Start on http://localhost:6006
```

Create `MyComponent.stories.tsx`:

```typescript
import type { Meta, StoryObj } from '@storybook/react'
import { MyComponent } from './MyComponent'

const meta: Meta<typeof MyComponent> = {
  title: 'Components/MyComponent',
  component: MyComponent,
}

export default meta
type Story = StoryObj<typeof MyComponent>

export const Default: Story = {
  args: {
    title: 'Hello',
  },
}

export const Loading: Story = {
  args: {
    loading: true,
  },
}
```

## Need Help?

- 📖 Full docs: [TESTING.md](./TESTING.md)
- 📊 Implementation summary: [TEST_IMPLEMENTATION_SUMMARY.md](./TEST_IMPLEMENTATION_SUMMARY.md)
- 💡 Examples: Look at `__tests__/` folders for patterns
- 🐛 Issues: Check Vitest UI for detailed error messages

## Coverage

Check coverage after writing tests:

```bash
npm run test:coverage
```

Opens HTML report in `coverage/index.html`

Target: **70% coverage** for lines, functions, branches, statements

---

**Try it now!** Run `npm run test:watch` and start writing tests. Vitest will re-run automatically as you save files.
