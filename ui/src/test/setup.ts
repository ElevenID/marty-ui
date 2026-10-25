/**
 * Vitest Test Setup
 * 
 * - Configures testing-library matchers
 * - Sets up Mock Service Worker (MSW) for API mocking
 * - Mocks environment variables
 * - Configures global test utilities
 */

import '@testing-library/jest-dom'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach, beforeAll, afterAll, vi } from 'vitest'
import { server } from './mocks/server'

// Mock environment variables
vi.stubGlobal('import.meta', {
  env: {
    VITE_API_URL: 'http://localhost:8000',
    MODE: 'test',
    DEV: false,
    PROD: false,
    SSR: false,
  },
})

// Start MSW server before all tests
beforeAll(() => {
  server.listen({
    onUnhandledRequest: 'warn',
  })
})

// jsdom can report Document as the previous focus target after a focused
// portal is removed. Start each case with an actual focusable DOM target so
// MUI's restore-focus behavior is exercised against browser-like focus state.
let originalBodyTabIndex: string | null = null
beforeEach(() => {
  originalBodyTabIndex = document.body.getAttribute('tabindex')
  document.body.tabIndex = -1
  document.body.focus()
})

// Reset handlers and cleanup after each test
afterEach(() => {
  server.resetHandlers()
  cleanup()
  if (originalBodyTabIndex == null) document.body.removeAttribute('tabindex')
  else document.body.setAttribute('tabindex', originalBodyTabIndex)
})

// Stop MSW server after all tests
afterAll(() => {
  server.close()
})

// Mock window.matchMedia (used by MUI components)
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock IntersectionObserver (used by some components)
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  takeRecords() {
    return []
  }
  unobserve() {}
} as any

// Mock ResizeObserver (used by some charting libraries)
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
} as any
