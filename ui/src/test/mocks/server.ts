/**
 * MSW Server for Node.js Environment
 * 
 * Used by Vitest for component/integration tests.
 */

import { setupServer } from 'msw/node'
import { handlers } from './handlers'

// Setup MSW server with default handlers
export const server = setupServer(...handlers)
