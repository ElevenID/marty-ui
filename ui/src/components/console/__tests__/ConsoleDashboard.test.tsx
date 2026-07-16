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
import { http, HttpResponse } from 'msw'
import { render } from '@test/utils'
import { server } from '@test/mocks/server'
import ConsoleDashboard from '../ConsoleDashboard'

const mockNavigate = vi.fn()

// Mock auth hook
vi.mock('@hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 1, name: 'Admin User', capabilities: { 'admin:platform': true } },
    organizationName: 'Test Organization',
    organizationId: 'org_123',
    isAdministrator: true,
    isVendor: false,
  }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: 'org_123',
    memberships: [{ id: 'org_123', display_name: 'Test Organization' }],
  }),
}))

// Mock SSE (not needed for rendering tests)
vi.mock('@hooks/useSSE', () => ({
  useSSE: () => ({ isConnected: false }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

// Dashboard data fixtures
const emptyDashboardData = {
  trustProfiles: [],
  signingKeys: [{ id: 'key_1', name: 'Issuer Key' }],
  issuerProfiles: [],
  keyManagementConfig: {
    default_service_id: 'managed-openbao-transit',
    services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
  },
  templates: [],
  policies: [],
  deployments: [],
  flows: [],
  apiKeys: [],
  systemHealth: { gateway: 'healthy', issuer: 'healthy', verifier: 'healthy' },
  teamData: { members: [], pendingInvites: [], roleDistribution: { admin: 0, developer: 0, operator: 0 } },
  runtimeStatus: { canIssue: false, canVerify: false, issuerKeysValid: false, issuerActive: false, deploymentActive: false, policyReachable: false },
  criticalEvents: [],
  environment: 'development',
  lifecycle: null,
}

const partialDashboardData = {
  trustProfiles: [{ id: 1, name: 'Active Profile', status: 'active' }],
  signingKeys: [{ id: 'key_1', name: 'Issuer Key' }],
  issuerProfiles: [{
    id: 'issuer_1',
    issuer_did: 'did:web:issuer.example.com',
    signing_service_id: 'managed-openbao-transit',
    status: 'active',
  }],
  keyManagementConfig: {
    default_service_id: 'managed-openbao-transit',
    services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
  },
  templates: [{
    id: 1,
    name: 'Test Template',
    status: 'active',
    artifacts_status: 'missing',
    trust_profile_id: 1,
    issuer_profile_id: 'issuer_1',
    key_access_mode: 'REMOTE_SIGNING',
  }],
  policies: [],
  deployments: [],
  flows: [],
  apiKeys: [],
  systemHealth: { gateway: 'healthy', issuer: 'healthy', verifier: 'healthy' },
  teamData: { members: [{ id: 'u1', name: 'Admin', role: 'admin' }], pendingInvites: [], roleDistribution: { admin: 1, developer: 0, operator: 0 } },
  runtimeStatus: { canIssue: false, canVerify: false, issuerKeysValid: false, issuerActive: false, deploymentActive: false, policyReachable: false },
  criticalEvents: [],
  environment: 'development',
  lifecycle: null,
}

const fullDashboardData = {
  trustProfiles: [{ id: 1, name: 'Active Profile', status: 'active' }],
  signingKeys: [{ id: 'key_1', name: 'Issuer Key' }],
  issuerProfiles: [{
    id: 'issuer_1',
    issuer_did: 'did:web:issuer.example.com',
    signing_service_id: 'managed-openbao-transit',
    status: 'active',
  }],
  keyManagementConfig: {
    default_service_id: 'managed-openbao-transit',
    services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
  },
  templates: [{
    id: 1,
    name: 'Test Template',
    status: 'active',
    artifacts_status: 'valid',
    trust_profile_id: 1,
    issuer_profile_id: 'issuer_1',
    key_access_mode: 'REMOTE_SIGNING',
  }],
  policies: [{ id: 1, name: 'Test Policy', status: 'active', required_claims: ['age'] }],
  deployments: [{ id: 1, name: 'Prod Deploy', status: 'active' }],
  flows: [{ id: 1, name: 'Verify Flow', status: 'active', trust_profile_id: 1, presentation_policy_id: 1 }],
  apiKeys: [{ id: 'key_1', name: 'Prod Key', status: 'active' }],
  systemHealth: { gateway: 'healthy', issuer: 'healthy', verifier: 'healthy' },
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
  lifecycle: null,
}

const hostedPilotLifecycle = {
  createdAt: new Date().toISOString(),
  complianceProfiles: [],
  planTier: 'starter',
  planExpiresAt: null,
  commercialOffer: 'Hosted Pilot',
  dataRetentionMode: 'hosted_pilot_rolling_purge',
  auditRetentionDays: 30,
  pilotRetention: {
    enabled: true,
    windowDays: 30,
    scopeSummary: 'Hosted Pilot data older than 30 days is purge-eligible while admin access stays available.',
    scopeItems: [
      'Applications and uploaded evidence',
      'Issuance transactions and linked issued credentials',
      'Authorization sessions',
      'Issuance lifecycle events',
    ],
    accessBehavior: 'Purge affects retained pilot data only. Organization access and configuration remain available.',
    lastPurgedAt: null,
    cutoffAt: null,
    nextExpiryAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(),
    oldestRetainedRecordAt: new Date().toISOString(),
    trackedScope: ['applications', 'submitted_evidence', 'issuance_transactions', 'issued_credentials', 'authorization_sessions', 'issuance_events'],
    eligibleForPurge: {
      issuanceTransactions: 0,
      applications: 0,
      authorizationSessions: 0,
      issuanceEvents: 0,
      issuedCredentials: 0,
      total: 0,
    },
  },
}

// Mock useDashboardData with a controllable return value
let mockDashboardReturn: any = { data: fullDashboardData, loading: false, error: null, refetch: vi.fn() }

vi.mock('@hooks/useDashboardData', () => ({
  useDashboardData: () => mockDashboardReturn,
}))

describe('ConsoleDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockNavigate.mockReset()
    mockDashboardReturn = { data: fullDashboardData, loading: false, error: null, refetch: vi.fn() }
    server.use(
      http.get('http://localhost:8000/v1/organizations/:orgId/dashboard/applicant-stats', () => HttpResponse.json({
        pending: 0,
        approved: 0,
        issuable: 0,
        total: 0,
      })),
      http.get('http://localhost:8000/api/issuance/analytics/summary', () => HttpResponse.json({
        active_offers: 0,
        total_scans: 0,
        success_rate: 100,
        total_offers: 0,
      })),
      http.post('http://localhost:8000/v1/organizations/:orgId/lifecycle/purge', () => HttpResponse.json({
        organization_id: 'org_123',
        retention_days: 30,
        cutoff_at: new Date().toISOString(),
        purged_at: new Date().toISOString(),
        next_expiry_at: null,
        oldest_retained_record_at: null,
        tracked_scope: ['applications', 'submitted_evidence', 'issuance_transactions', 'issued_credentials', 'authorization_sessions', 'issuance_events'],
        purged_records: {
          issuance_transactions: 1,
          applications: 1,
          authorization_sessions: 1,
          issuance_events: 1,
          issued_credentials: 0,
          total: 4,
        },
      })),
    )
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
      expect(screen.getByRole('tab', { name: /Verify credentials/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /Issue credentials/i })).toBeInTheDocument()
      expect(screen.getAllByText(/Trust Profile/i).length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText(/Presentation Policy/i).length).toBeGreaterThanOrEqual(1)
      expect(screen.queryByText(/^Credential Template$/i)).not.toBeInTheDocument()
    })

    it('should show all items as missing', () => {
      render(<ConsoleDashboard />)
      // All resources are MISSING in empty state — shown as unchecked circles
      const unchecked = screen.getAllByTestId('RadioButtonUncheckedIcon')
      expect(unchecked.length).toBeGreaterThanOrEqual(3)
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

    it('should show operational action buttons', () => {
      render(<ConsoleDashboard />)
      // In operational state, quick actions are hidden; operational banner buttons are shown
      expect(screen.getByRole('link', { name: /Go to Operate/i })).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /View Audit/i })).toBeInTheDocument()
    })

    it('should show recent activity panel', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Recent Activity/i)).toBeInTheDocument()
    })

    it('should show recent activity degradation with message id instead of empty activity', async () => {
      server.use(
        http.get('http://localhost:8000/v1/organizations/:orgId/audit-events', () => HttpResponse.json({
          error: 'service_error',
          error_description: {
            error: 'audit_log_unavailable',
            message: 'Organization audit log storage is not configured for this deployment.',
          },
          message_id: 'msg-recent-activity-1',
        }, { status: 501 }))
      )

      render(<ConsoleDashboard />)

      expect(await screen.findByText(/Recent activity unavailable/i)).toBeInTheDocument()
      expect(screen.getByText('Organization audit log storage is not configured for this deployment.')).toBeInTheDocument()
      expect(screen.getByText(/Message ID: msg-recent-activity-1/i)).toBeInTheDocument()
      expect(screen.queryByText(/Activity will appear here once you begin issuing or verifying credentials/i)).not.toBeInTheDocument()
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
      // Environment badge shows short label "Dev"
      expect(screen.getByText('Dev')).toBeInTheDocument()
    })

    it('should show environment warning for production', () => {
      mockDashboardReturn = { data: { ...fullDashboardData, environment: 'production' }, loading: false, error: null, refetch: vi.fn() }
      render(<ConsoleDashboard />)
      expect(screen.getAllByText(/Production Environment/i).length).toBeGreaterThanOrEqual(1)
    })

    it('should display environment context', () => {
      render(<ConsoleDashboard />)
      // Environment badge shows short label "Dev"
      expect(screen.getByText('Dev')).toBeInTheDocument()
    })

    it('should show unknown environment when environment loading fails', () => {
      mockDashboardReturn = {
        data: {
          ...fullDashboardData,
          environment: null,
          dashboardErrors: {
            environment: Object.assign(new Error('organization service unavailable'), {
              response: { message_id: 'msg-env-1' },
            }),
          },
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)

      expect(screen.getByText(/Environment unavailable/i)).toBeInTheDocument()
      expect(screen.getByText('Unknown')).toBeInTheDocument()
      expect(screen.queryByText('Dev')).not.toBeInTheDocument()
    })

    it('should render structured dashboard error envelopes without crashing', () => {
      mockDashboardReturn = {
        data: {
          ...fullDashboardData,
          dashboardErrors: {
            criticalEvents: {
              response: {
                error: 'service_error',
                error_description: {
                  error: 'audit_log_unavailable',
                  message: 'Organization audit log storage is not configured for this deployment.',
                },
                message_id: 'msg-audit-1',
              },
            },
          },
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)

      expect(screen.getByText(/Critical events unavailable/i)).toBeInTheDocument()
      expect(screen.getByText('Organization audit log storage is not configured for this deployment.')).toBeInTheDocument()
      expect(screen.getByText(/Message ID: msg-audit-1/i)).toBeInTheDocument()
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
        data: { ...fullDashboardData, systemHealth: { gateway: 'healthy', issuer: 'warning', verifier: 'healthy' } },
        loading: false, error: null, refetch: vi.fn(),
      }
      render(<ConsoleDashboard />)
      expect(screen.getAllByText(/Degraded/i).length).toBeGreaterThanOrEqual(1)
    })

    it('should show critical events panel', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Critical Signals/i)).toBeInTheDocument()
    })
  })

  describe('Team Snapshot', () => {
    it('should display team member count', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/5 members/i)).toBeInTheDocument()
    })

    it('should show role distribution', () => {
      render(<ConsoleDashboard />)
      // Role labels appear in team panel alongside welcome message
      expect(screen.getAllByText(/Admin/i).length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText(/Developer/i).length).toBeGreaterThanOrEqual(1)
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

    it('should route the trust quick action to the full trust profile wizard', async () => {
      const user = userEvent.setup()

      mockDashboardReturn = { data: emptyDashboardData, loading: false, error: null, refetch: vi.fn() }

      render(<ConsoleDashboard />)
      await user.click(screen.getByText('Create Trust Profile'))

      expect(mockNavigate).toHaveBeenCalledWith('/console/org/trust/profiles/new')
    })

    it('should route the template quick action to the credential template wizard', async () => {
      const user = userEvent.setup()

      mockDashboardReturn = {
        data: {
          ...emptyDashboardData,
          setupIntent: 'issue',
          trustProfiles: [{ id: 1, name: 'Active Profile', status: 'active' }],
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)
      await user.click(screen.getByText('Create Credential Template'))

      expect(mockNavigate).toHaveBeenCalledWith('/console/org/templates/credentials/new')
    })

    it('should route later setup quick actions to dedicated artifact wizards', async () => {
      const user = userEvent.setup()

      mockDashboardReturn = {
        data: {
          ...fullDashboardData,
          setupIntent: 'verify',
          policies: [],
          deployments: [],
          flows: [],
          apiKeys: [],
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      const { rerender } = render(<ConsoleDashboard />)
      await user.click(screen.getByText('Create Presentation Policy'))
      expect(mockNavigate).toHaveBeenCalledWith('/console/org/policies/presentation/new')

      mockNavigate.mockClear()
      mockDashboardReturn = {
        data: {
          ...fullDashboardData,
          flows: [],
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }
      rerender(<ConsoleDashboard />)
      expect(screen.queryByText('Create API Key')).not.toBeInTheDocument()
      await user.click(screen.getByText('Create Flow'))
      expect(mockNavigate).toHaveBeenCalledWith('/console/org/flows/definitions/new')
    })

    it('should prioritize signing service setup when trust dependencies are blocked by KMS', () => {
      mockDashboardReturn = {
        data: {
          ...emptyDashboardData,
          setupIntent: 'issue',
          signingKeys: [],
          issuerProfiles: [],
          keyManagementConfig: {
            default_service_id: null,
            services: [],
          },
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)

      expect(screen.getByText('Register Signing Service')).toBeInTheDocument()
      expect(screen.queryByText('Create Trust Profile')).not.toBeInTheDocument()
    })

    it('should prioritize issuer identity setup when KMS is ready but issuer input is missing', () => {
      mockDashboardReturn = {
        data: {
          ...emptyDashboardData,
          setupIntent: 'issue',
          signingKeys: [],
          issuerProfiles: [],
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)

      expect(screen.getAllByText('Set Up Issuer Identity').length).toBeGreaterThan(0)
      expect(screen.queryByText('Create Trust Profile')).not.toBeInTheDocument()
    })

    it('should show operational banner when fully configured', () => {
      render(<ConsoleDashboard />)
      expect(screen.getByText(/Organization is Operational/i)).toBeInTheDocument()
    })
  })

  describe('Hosted Pilot Retention', () => {
    it('should show the Hosted Pilot countdown banner when retention is enabled', () => {
      mockDashboardReturn = {
        data: { ...partialDashboardData, lifecycle: hostedPilotLifecycle },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)

      expect(screen.getByText(/Hosted Pilot retention/i)).toBeInTheDocument()
      expect(screen.getByText(/Next Hosted Pilot record ages out in/i)).toBeInTheDocument()
    })

    it('should allow a manual Hosted Pilot purge', async () => {
      const user = userEvent.setup()
      mockDashboardReturn = {
        data: {
          ...partialDashboardData,
          lifecycle: {
            ...hostedPilotLifecycle,
            pilotRetention: {
              ...hostedPilotLifecycle.pilotRetention,
              nextExpiryAt: null,
              eligibleForPurge: {
                issuanceTransactions: 1,
                applications: 1,
                authorizationSessions: 1,
                issuanceEvents: 1,
                issuedCredentials: 0,
                total: 4,
              },
            },
          },
        },
        loading: false,
        error: null,
        refetch: vi.fn(),
      }

      render(<ConsoleDashboard />)
      await user.click(screen.getByRole('button', { name: /Purge now/i }))

      await waitFor(() => {
        expect(screen.getByText(/Purged 4 Hosted Pilot records/i)).toBeInTheDocument()
      })
    })
  })
})
