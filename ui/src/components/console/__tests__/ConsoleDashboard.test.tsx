/**
 * Integration Tests for Console Dashboard
 * 
 * Tests dashboard rendering with different organization states:
 * - Empty (no configuration)
 * - Partially configured
 * - Fully operational
 * - With blockers/errors
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { render } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import { emptyOrgHandlers, partiallyConfiguredHandlers } from '@test/mocks/handlers'
import ConsoleDashboard from '../ConsoleDashboard'

// Mock auth hook
vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 1, name: 'Admin User', capabilities: { 'admin:platform': true } },
    organizationName: 'Test Organization',
    organizationId: 'org_123',
    isAdmin: true,
  }),
}))

describe('ConsoleDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Empty Organization State', () => {
    beforeEach(() => {
      // Use empty org MSW handlers
      server.use(...emptyOrgHandlers)
    })

    it('should render dashboard with loading state', () => {
      render(<ConsoleDashboard />)

      // Should show some dashboard structure even while loading
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })

    it('should show setup readiness as incomplete', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/setup readiness/i)).toBeInTheDocument()
      })

      // All items should show as not ready
      expect(screen.getByText(/trust profile/i)).toBeInTheDocument()
      expect(screen.getByText(/credential template/i)).toBeInTheDocument()
      expect(screen.getByText(/presentation policy/i)).toBeInTheDocument()
    })

    it('should show blocking issues', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/blocking issues/i)).toBeInTheDocument()
      })

      // Should indicate missing configuration
      expect(screen.getByText(/create a trust profile/i)).toBeInTheDocument()
    })

    it('should enable trust profile quick action', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        const trustAction = screen.getByText(/trust profile/i)
        expect(trustAction).toBeInTheDocument()
      })

      // Trust profile should be enabled (first step)
      const trustCard = screen.getByText(/trust profile/i).closest('.MuiCard-root')
      expect(trustCard).not.toHaveStyle({ opacity: '0.6' })
    })

    it('should disable downstream quick actions', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/deployment profile/i)).toBeInTheDocument()
      })

      // Actions requiring prerequisites should be disabled
      const deploymentCard = screen.getByText(/deployment profile/i).closest('.MuiCard-root')
      expect(deploymentCard).toHaveStyle({ opacity: '0.6' })
    })

    it('should show tooltips for disabled actions', async () => {
      const user = userEvent.setup()
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/flow definition/i)).toBeInTheDocument()
      })

      // Hover over disabled action
      const flowCard = screen.getByText(/flow definition/i).closest('.MuiCard-root')!
      await user.hover(flowCard)

      // Tooltip should explain why it's disabled
      await waitFor(() => {
        expect(screen.getByText(/requires deployment profile/i)).toBeInTheDocument()
      })
    })
  })

  describe('Partially Configured Organization', () => {
    beforeEach(() => {
      server.use(...partiallyConfiguredHandlers)
    })

    it('should show partial setup progress', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/setup readiness/i)).toBeInTheDocument()
      })

      // Some items ready, others not
      const trustStatus = screen.getByText(/trust profile/i).closest('.MuiListItem-root')
      expect(within(trustStatus!).getByTestId('CheckCircleIcon')).toBeInTheDocument()

      const flowStatus = screen.getByText(/flow definition/i).closest('.MuiListItem-root')
      expect(within(flowStatus!).getByTestId('CancelIcon')).toBeInTheDocument()
    })

    it('should enable next available actions', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/credential template/i)).toBeInTheDocument()
      })

      // Templates should be enabled now (trust profile exists)
      const templateCard = screen.getByText(/credential template/i).closest('.MuiCard-root')
      expect(templateCard).not.toHaveStyle({ opacity: '0.6' })
    })

    it('should show updated blockers', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/blocking issues/i)).toBeInTheDocument()
      })

      // Should prompt for next missing piece
      expect(screen.getByText(/create a flow definition/i)).toBeInTheDocument()
    })

    it('should calculate correct progress percentage', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        // Linear progress or percentage display
        const progress = screen.getByRole('progressbar')
        expect(progress).toHaveAttribute('aria-valuenow', '60') // 3 of 5 complete
      })
    })
  })

  describe('Fully Operational Organization', () => {
    beforeEach(() => {
      // Use default handlers (fully configured)
      server.resetHandlers()
    })

    it('should show operational status', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/organization is operational/i)).toBeInTheDocument()
      })

      // Success banner
      expect(screen.getByText(/all systems configured/i)).toBeInTheDocument()
    })

    it('should show all setup items as complete', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/setup readiness/i)).toBeInTheDocument()
      })

      // All checkmarks
      const checkmarks = screen.getAllByTestId('CheckCircleIcon')
      expect(checkmarks.length).toBeGreaterThan(3)
    })

    it('should show runtime capabilities', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/runtime readiness/i)).toBeInTheDocument()
      })

      // Can issue and verify
      expect(screen.getByText(/can issue credentials/i)).toBeInTheDocument()
      expect(screen.getByText(/can verify credentials/i)).toBeInTheDocument()
    })

    it('should enable all quick actions', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        const actions = screen.getAllByText(/get started/i)
        expect(actions.length).toBeGreaterThan(0)
      })

      // All action cards should be enabled
      const cards = screen.getAllByRole('button', { name: /get started/i })
      cards.forEach((card) => {
        expect(card).not.toBeDisabled()
      })
    })

    it('should show recent activity', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/recent activity/i)).toBeInTheDocument()
      })

      // Should show recent events
      expect(screen.getByText(/credential issued/i)).toBeInTheDocument()
    })

    it('should link to operate page', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/organization is operational/i)).toBeInTheDocument()
      })

      const operateLink = screen.getByRole('link', { name: /go to operations/i })
      expect(operateLink).toHaveAttribute('href', '/console/operate')
    })
  })

  describe('Environment Management', () => {
    it('should display current environment', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/development/i)).toBeInTheDocument()
      })
    })

    it('should show environment warning for production', async () => {
      const user = userEvent.setup()
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/environment/i)).toBeInTheDocument()
      })

      // Switch to production
      const envSwitcher = screen.getByLabelText(/select environment/i)
      await user.click(envSwitcher)
      await user.click(screen.getByText(/production/i))

      // Warning banner should appear
      await waitFor(() => {
        expect(screen.getByText(/production environment/i)).toBeInTheDocument()
      })
    })

    it('should update environment via API', async () => {
      const user = userEvent.setup()
      
      let updatedEnv: string | undefined
      server.use(
        http.patch('http://localhost:8000/v1/organizations/:id/environment', async ({ request }) => {
          const data = await request.json()
          updatedEnv = data.environment
          return HttpResponse.json({ environment: updatedEnv })
        })
      )

      render(<ConsoleDashboard />)

      await waitFor(() => screen.getByLabelText(/select environment/i))

      const envSwitcher = screen.getByLabelText(/select environment/i)
      await user.click(envSwitcher)
      await user.click(screen.getByText(/staging/i))

      await waitFor(() => {
        expect(updatedEnv).toBe('staging')
      })
    })
  })

  describe('System Health', () => {
    it('should show system status bar', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/system status/i)).toBeInTheDocument()
      })

      // Health indicators
      expect(screen.getByText(/api/i)).toBeInTheDocument()
      expect(screen.getByText(/database/i)).toBeInTheDocument()
    })

    it('should indicate degraded services', async () => {
      server.use(
        http.get('http://localhost:8000/v1/dashboard/data', () => {
          return HttpResponse.json({
            systemHealth: {
              api: 'healthy',
              database: 'degraded',
              redis: 'healthy',
            },
          })
        })
      )

      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/degraded/i)).toBeInTheDocument()
      })
    })

    it('should show critical events panel', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/critical events/i)).toBeInTheDocument()
      })
    })
  })

  describe('Team Snapshot', () => {
    it('should display team member count', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/team snapshot/i)).toBeInTheDocument()
      })

      expect(screen.getByText(/5 members/i)).toBeInTheDocument()
    })

    it('should show online status', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/3 online/i)).toBeInTheDocument()
      })
    })
  })

  describe('Error States', () => {
    it('should handle API errors gracefully', async () => {
      server.use(
        http.get('http://localhost:8000/v1/dashboard/data', () => {
          return HttpResponse.json(
            { error: { message: 'Internal server error' } },
            { status: 500 }
          )
        })
      )

      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(screen.getByText(/error loading dashboard/i)).toBeInTheDocument()
      })
    })

    it('should retry failed requests', async () => {
      let attempts = 0
      server.use(
        http.get('http://localhost:8000/v1/dashboard/data', () => {
          attempts++
          if (attempts === 1) {
            return HttpResponse.error()
          }
          return HttpResponse.json({ readiness: {}, runtimeStatus: {} })
        })
      )

      render(<ConsoleDashboard />)

      await waitFor(() => {
        expect(attempts).toBeGreaterThan(1)
      })
    })
  })

  describe('Quick Action Navigation', () => {
    it('should navigate to trust profile wizard', async () => {
      const user = userEvent.setup()
      render(<ConsoleDashboard />)

      await waitFor(() => screen.getByText(/trust profile/i))

      const trustAction = screen.getByText(/trust profile/i)
        .closest('.MuiCard-root')!
        .querySelector('a')!
      
      expect(trustAction).toHaveAttribute('href', '/console/trust/create')
    })

    it('should navigate to template wizard', async () => {
      render(<ConsoleDashboard />)

      await waitFor(() => screen.getByText(/credential template/i))

      const templateLink = screen.getByText(/credential template/i)
        .closest('.MuiCard-root')!
        .querySelector('a')!
      
      expect(templateLink).toHaveAttribute('href', '/console/templates/create')
    })
  })
})
