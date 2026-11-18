/**
 * Dashboard Readiness Card Story
 * 
 * Example story demonstrating:
 * - MSW API mocking
 * - Multiple scenarios (empty, blocked, ready)
 * - Interactive controls
 */

import type { Meta, StoryObj } from '@storybook/react'
import { http, HttpResponse } from 'msw'
import { Box } from '@mui/material'
import { 
  dashboardScenarios, 
  mockTrustProfiles 
} from '@test/mocks/fixtures'

// Import the actual component when it's refactored to be story-friendly
// For now, this is a placeholder showing the pattern
const DashboardReadinessCard = ({ title, status, message }: any) => (
  <Box sx={{ p: 2, border: '1px solid #ccc', borderRadius: 1 }}>
    <h3>{title}</h3>
    <p>Status: {status}</p>
    <p>{message}</p>
  </Box>
)

const meta: Meta<typeof DashboardReadinessCard> = {
  title: 'Dashboard/ReadinessCard',
  component: DashboardReadinessCard,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
}

export default meta
type Story = StoryObj<typeof DashboardReadinessCard>

/**
 * Default state - empty organization
 */
export const Empty: Story = {
  args: {
    title: 'Trust Profile',
    status: 'missing',
    message: 'No Trust Profiles configured',
  },
  parameters: {
    msw: {
      handlers: [
        http.get('/v1/trust-profiles', () => {
          return HttpResponse.json([])
        }),
      ],
    },
  },
}

/**
 * Blocked state - profile exists but inactive
 */
export const Blocked: Story = {
  args: {
    title: 'Trust Profile',
    status: 'blocked',
    message: '1 Trust Profile configured but none active',
  },
  parameters: {
    msw: {
      handlers: [
        http.get('/v1/trust-profiles', () => {
          return HttpResponse.json([mockTrustProfiles.inactive])
        }),
      ],
    },
  },
}

/**
 * Ready state - active profile exists
 */
export const Ready: Story = {
  args: {
    title: 'Trust Profile',
    status: 'ready',
    message: '1 active Trust Profile',
  },
  parameters: {
    msw: {
      handlers: [
        http.get('/v1/trust-profiles', () => {
          return HttpResponse.json([mockTrustProfiles.active])
        }),
      ],
    },
  },
}

/**
 * Error state - API failure
 */
export const Error: Story = {
  args: {
    title: 'Trust Profile',
    status: 'error',
    message: 'Failed to load trust profiles',
  },
  parameters: {
    msw: {
      handlers: [
        http.get('/v1/trust-profiles', () => {
          return HttpResponse.json(
            { error: { message: 'Internal server error' } },
            { status: 500 }
          )
        }),
      ],
    },
  },
}
