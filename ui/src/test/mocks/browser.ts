/**
 * MSW Browser Worker
 * 
 * Used by Storybook and browser-based development/testing.
 * Run `setupWorker()` in your app's entry point for development mode.
 */

import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'

// Setup MSW browser worker with default handlers
export const worker = setupWorker(...handlers)
