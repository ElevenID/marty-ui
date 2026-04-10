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
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { render } from '@test/utils'
import ConsoleDashboard from '../ConsoleDashboard'

// Mock auth hook
vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 1, name: 'Admin User', capabilities: { 'admin:platform': true } },
    organizationName: 'Test Organization',
    organizationId: 'org_123',
    isAdministrator: true,
    isVendor: false,
  }),
}))

// Mock SSE (not needed for rendering tests)
vi.mock('../../hooks/useSSE', () => ({
  useSSE: () => ({ isConnected: false }),
}))

// Dashboard data fixtures
const emptyDashboardData = {
  trustProfiles: [],
  templates: [],
  policies: [],
  deployments: [],
  flows: [],
  apiKeys: [],
  systemHealth: { api: 'healthy', issuer: 'healthy', verifier: 'healthy' },
  teamData: { members: [], pendingInvites: [], roleDistribution: { admin: 0, developer: 0, operator: 0 } },
  runtimeStatus: { canIssue: false, canVerify: false, issuerKeysValid: false, issuerActive: false, deploymentActive: false, policyReachable: false },
  criticalEvents: [],
  environment: 'development',
}

const partialDashboardData = {
  trustProfiles: [{ id: 1, name: 'Active Profile', status: 'active' }],
  templates: [{ id: 1, name: 'Test Template', status: 'active', artifacts_status: 'missing', trust_profile_id: 1 }],
  policies: [],
  deployments: [],
  flows: [],
  apiKeys: [],
  systemHealth: { api: 'healthy', issuer: 'healthy', verifier: 'healthy' },
  teamData: { members: [{ id: 'u1', name: 'Admin', role: 'admin' }], pendingInvites: [], roleDistribution: { admin: 1, developer: 0, operator: 0 } },
  runtimeStatus: { canIssue: false, canVerify: false, issuerKeysValid: false, issuerActive: false, deploymentActive: false, policyReachable: false },
  criticalEvents: [],
  environment: 'development',
}

const fullDashboardData = {
  trustProfiles: [{ id: 1, name: 'Active Profile', status: 'active' }],
  templates: [{ id: 1, name: 'Test Template', status: 'active', artifacts_status: 'valid', trust_profile_id: 1 }],
  policies: [{ id: 1, name: 'Test Policy', status: 'active', required_claims: ['age'] }],
  deployments: [{ id: 1, name: 'Prod Deploy', status: 'active' }],
  flows: [{ id: 1, name: 'Verify Flow', status: 'active', trust_profile_id: 1, presentation_policy_id: 1 }],
  apiKeys: [{ id: 'key_1', name: 'Prod Key', status: 'active' }],
  systemHealth: { api: 'healthy', issuer: 'healthy', verifier: 'healthy' },
  teamData: {
    members: [
      { id: 'u1', name: 'Admin User', role: 'admin', status: 'online' },
      { id: 'u2', name: 'Dev User', role: 'developer', status: 'online' },
      { id: 'u3', name: 'Dev User 2', role: 'developer', status: 'offline' },
      { id: 'u4', name: 'Operator', role: 'operator', status: 'online' },
      { id: 'u5', name: 'Operator 2', role: 'operator', status: 'offline' },
    ],
    pendingInvites: [],
    roleDistribution: { admin: 1, developer: 2, operator: 2 },
  },
  runtimeStatus: { canIssue: true, canVerify: true, issuerKeysValid: true, issuerActive: true, deploymentActive: true, policyReachable: true, lastIssuance: new Date().toISOString(), lastVerification: new Date().toISOString() },
  criticalEvents: [],
  environment: 'development',
}

// Mock useDashboardData with a controllable return value
let mockDashboardReturn: any = { data: fullDashboardData, loading: false, error: null, refetch: vi.fn() }

vi.mock('../../hooks/useDashboardData', () => ({
  useDashboardData: () => mockDashboardReturn,
}))

describe('ConsoleDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockDashboardReturn = { data: fullDashboardData, loading: false, error: null, refetch: vi.fn() }
  })

  describe('Empty Organization State', () => {
    beforeEach(() => {
      mockDashboardReturn = { data: emptyDashboardData, loading: false, error: null, refetch: vi.fn() }
    })

    it('should render dashboard title', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })

    it('should show setup readiness as incomplete', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Setup Readiness/i)).toBeInTheDocument()
      expect(screen.getByText(/Trust Profile/i)).toBeInTheDocument()
      expect(screen.getByText(/Credential Template/i)).toBeInTheDocument()
      expect(screen.getByText(/Presentation Policy/i)).toBeInTheDocument()
    })

    it('should show all items as missing', () => {
      render(<ConsoleDashboard />)
      // All resources are MISSING in empty state — shown as unchecked circles
      const unchecked = screen.getAllByTestId('RadioButtonUncheckedIcon')
      expect(unchecked.length).toBeGreaterThanOrEqual(5)
    })

    it('should show quick actions for setup', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Next Step/i)).toBeInTheDocument()
    })

    it('should show team panel with no members', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/No team members yet/i)).toBeInTheDocument()
    })

    it('should show system status', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/System Status/i)).toBeInTheDocument()
    })
  })

  describe('Partially Configured Organization', () => {
    beforeEach(() => {
      mockDashboardReturn = { data: partialDashboardData, loading: false, error: null, refetch: vi.fn() }
    })

    it('should show partial setup progress', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Setup Readiness/i)).toBeInTheDocument()

      // Trust is ready — should have at least one CheckCircleIcon
      const checkmarks = screen.getAllByTestId('CheckCircleIcon')
      expect(checkmarks.length).toBeGreaterThanOrEqual(1)

      // Template is BLOCKED — should have WarningIcon
      const warnings = screen.getAllByTestId('WarningIcon')
      expect(warnings.length).toBeGreaterThanOrEqual(1)
    })

    it('should show quick actions', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Next Step/i)).toBeInTheDocument()
    })

    it('should show blocking issues for blocked template', () => {
      render(<ConsoleDashboard />)
      // Template has artifacts_status: 'missing' — computeBlockers returns blocker
      expect(screen.getByText(/Blocking Issues/i)).toBeInTheDocument()
    })

    it('should show team with one member', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/1 member\b/)).toBeInTheDocument()
    })
  })

  describe('Fully Operational Organization', () => {
    beforeEach(() => {
      mockDashboardReturn = { data: fullDashboardData, loading: false, error: null, refetch: vi.fn() }
    })

    it('should show operational status', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Organization is Operational/i)).toBeInTheDocument()
    })

    it('should show all setup items as complete', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Setup Readiness/i)).toBeInTheDocument()
      const checkmarks = screen.getAllByTestId('CheckCircleIcon')
      expect(checkmarks.length).toBeGreaterThanOrEqual(5)
    })

    it('should show runtime readiness', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Runtime Operational Status/i)).toBeInTheDocument()
    })

    it('should enable all quick actions', async () => {
      render(<ConsoleDashboard />)
      await waitFor(() => {
        const actions = screen.getAllByText(/get started/i)
        expect(actions.length).toBeGreaterThan(0)
      })
      const cards = screen.getAllByRole('button', { name: /get started/i })
      cards.forEach((card) => {
        expect(card).not.toBeDisabled()
      })
    })

    it('should show recent activity panel', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Recent Activity/i)).toBeInTheDocument()
    })

    it('should link to operate page', () => {
      render(<ConsoleDashboard />)
      const operateLink = screen.getByRole('link', { name: /Go to Operate/i })
      expect(operateLink).toHaveAttribute('href', '/console/org/operate')
    })
  })

  describe('Environment Management', () => {
    it('should display current environment', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Development/i)).toBeInTheDocument()
    })

    it('should show environment warning for production', () => {
      mockDashboardReturn = { data: { ...fullDashboardData, environment: 'production' }, loading: false, error: null, refetch: vi.fn() }
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Production Environment/i)).toBeInTheDocument()
    })

    it('should display environment context', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Development/i)).toBeInTheDocument()
    })
  })

  describe('System Health', () => {
    it('should show system status bar', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/System Status/i)).toBeInTheDocument()
      expect(screen.getByText(/API Gateway/i)).toBeInTheDocument()
    })

    it('should indicate degraded services', () => {
      mockDashboardReturn = {
        data: { ...fullDashboardData, systemHealth: { api: 'healthy', issuer: 'degraded', verifier: 'healthy' } },
        loading: false, error: null, refetch: vi.fn(),
      }
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Degraded/i)).toBeInTheDocument()
    })

    it('should show critical events panel', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Critical/i)).toBeInTheDocument()
    })
  })

  describe('Team Snapshot', () => {
    it('should display team member count', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/5 members/i)).toBeInTheDocument()
    })

    it('should show role distribution', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Admin/i)).toBeInTheDocument()
      expect(screen.getByText(/Developer/i)).toBeInTheDocument()
    })
  })

  describe('Error States', () => {
    it('should handle API errors gracefully', () => {
      mockDashboardReturn = { data: emptyDashboardData, loading: false, error: 'Internal server error', refetch: vi.fn() }
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Error loading dashboard/i)).toBeInTheDocument()
    })

    it('should show loading state', () => {
      mockDashboardReturn = { data: emptyDashboardData, loading: true, error: null, refetch: vi.fn() }
      render(<ConsoleDashboard />)
      expect(screen.getByRole('progressbar')).toBeInTheDocument()
    })
  })

  describe('Quick Action Navigation', () => {
    it('should show quick actions when not operational', () => {
      mockDashboardReturn = { data: emptyDashboardData, loading: false, error: null, refetch: vi.fn() }
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Next Step/i)).toBeInTheDocument()
    })

    it('should show operational banner when fully configured', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Organization is Operational/i)).toBeInTheDocument()
    })
  })
})
