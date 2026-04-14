/**
 * MSW Request Handlers
 * 
 * Mock API handlers for testing and Storybook.
 * Matches the API structure from services/*.jsx files.
 */

import { http, HttpResponse } from 'msw'
import {
  mockUsers,
  mockOrganization,
  mockTrustProfiles,
  mockTemplates,
  mockPolicies,
  mockDeploymentProfiles,
  mockFlows,
  dashboardScenarios,
  mockErrors,
} from './fixtures'

const API_BASE = 'http://localhost:8000'

/**
 * Error response helpers for realistic UX testing
 * Following UX-driven test strategy with user-visible error states
 */
export const errorResponses = {
  // 400 Bad Request - Validation errors
  validationError: (field: string, message: string) =>
    HttpResponse.json(
      {
        error: {
          code: 'VALIDATION_ERROR',
          message: `Validation failed: ${message}`,
          details: { [field]: message },
        },
      },
      { status: 400 }
    ),

  // 401 Unauthorized - Auth required
  unauthorized: () =>
    HttpResponse.json(
      {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required. Please log in.',
        },
      },
      { status: 401 }
    ),

  // 403 Forbidden - Insufficient permissions
  forbidden: (resource: string) =>
    HttpResponse.json(
      {
        error: {
          code: 'FORBIDDEN',
          message: `You don't have permission to access ${resource}`,
        },
      },
      { status: 403 }
    ),

  // 404 Not Found
  notFound: (resource: string) =>
    HttpResponse.json(
      {
        error: {
          code: 'NOT_FOUND',
          message: `${resource} not found`,
        },
      },
      { status: 404 }
    ),

  // 409 Conflict - Resource already exists
  conflict: (message: string) =>
    HttpResponse.json(
      {
        error: {
          code: 'CONFLICT',
          message,
        },
      },
      { status: 409 }
    ),

  // 500 Server Error
  serverError: () =>
    HttpResponse.json(
      {
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected error occurred. Please try again later.',
        },
      },
      { status: 500 }
    ),

  // 503 Service Unavailable
  serviceUnavailable: () =>
    HttpResponse.json(
      {
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: 'Service temporarily unavailable. Please try again.',
        },
      },
      { status: 503 }
    ),

  // Network timeout (delay then error)
  timeout: async () => {
    await new Promise((resolve) => setTimeout(resolve, 5000))
    return HttpResponse.json(
      {
        error: {
          code: 'TIMEOUT',
          message: 'Request timed out. Please check your connection.',
        },
      },
      { status: 408 }
    )
  },
}

export const handlers = [
  // Auth endpoints
  http.post(`${API_BASE}/auth/login`, async ({ request }) => {
    const body = await request.json() as any
    const { username, password } = body

    if (password === 'wrong') {
      return HttpResponse.json(mockErrors.unauthorized, { status: 401 })
    }

    // Return user based on username
    let user: any = mockUsers.admin
    if (username.includes('vendor')) {
      user = mockUsers.vendor
    } else if (username.includes('applicant')) {
      user = mockUsers.applicant
    }

    return HttpResponse.json({
      user,
      token: 'mock-jwt-token',
    })
  }),

  http.post(`${API_BASE}/auth/logout`, () => {
    return HttpResponse.json({ message: 'Logged out successfully' })
  }),

  http.get(`${API_BASE}/auth/me`, () => {
    return HttpResponse.json({ authenticated: true, user: mockUsers.admin })
  }),
  http.get(`${API_BASE}/v1/auth/me`, () => {
    return HttpResponse.json({ authenticated: true, user: mockUsers.admin })
  }),
  http.get(`${API_BASE}/v1/auth/me/organizations`, () => {
    return HttpResponse.json({ organizations: [mockOrganization] })
  }),

  // Organizations
  http.get(`${API_BASE}/v1/organizations`, () => {
    return HttpResponse.json([mockOrganization])
  }),

  http.get(`${API_BASE}/v1/organizations/:id`, ({ params }) => {
    return HttpResponse.json(mockOrganization)
  }),

  // Trust Profiles
  http.get(`${API_BASE}/v1/trust-profiles`, () => {
    return HttpResponse.json([mockTrustProfiles.active])
  }),

  http.get(`${API_BASE}/v1/trust-profiles/:id`, ({ params }) => {
    return HttpResponse.json(mockTrustProfiles.active)
  }),

  http.get(`${API_BASE}/v1/trust-profiles/:id/issuers`, () => {
    return HttpResponse.json(mockTrustProfiles.active.trusted_issuers)
  }),

  http.post(`${API_BASE}/v1/trust-profiles`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTrustProfiles.active,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.patch(`${API_BASE}/v1/trust-profiles/:id`, async ({ params, request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTrustProfiles.active,
      ...body,
      id: params.id,
    })
  }),

  http.post(`${API_BASE}/v1/trust-profiles/:id/issuers`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      id: 'issuer-link-created',
      status: 'active',
      ...body,
    }, { status: 201 })
  }),

  http.delete(`${API_BASE}/v1/trust-profiles/:id`, () => {
    return HttpResponse.json({ message: 'Deleted successfully' })
  }),

  // Credential Templates
  http.get(`${API_BASE}/v1/credential-templates`, () => {
    return HttpResponse.json([mockTemplates.valid])
  }),

  http.get(`${API_BASE}/v1/credential-templates/:id`, ({ params }) => {
    return HttpResponse.json(mockTemplates.valid)
  }),

  http.post(`${API_BASE}/v1/credential-templates`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTemplates.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.patch(`${API_BASE}/v1/credential-templates/:id`, async ({ params, request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTemplates.valid,
      ...body,
      id: params.id,
    })
  }),

  http.delete(`${API_BASE}/v1/credential-templates/:id`, () => {
    return HttpResponse.json({ message: 'Deleted successfully' })
  }),

  // Presentation Policies
  http.get(`${API_BASE}/v1/presentation-policies`, () => {
    return HttpResponse.json([mockPolicies.valid])
  }),

  http.get(`${API_BASE}/v1/presentation-policies/:id`, ({ params }) => {
    return HttpResponse.json(mockPolicies.valid)
  }),

  http.post(`${API_BASE}/v1/presentation-policies`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockPolicies.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.patch(`${API_BASE}/v1/presentation-policies/:id`, async ({ params, request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockPolicies.valid,
      ...body,
      id: params.id,
    })
  }),

  http.delete(`${API_BASE}/v1/presentation-policies/:id`, () => {
    return HttpResponse.json({ message: 'Deleted successfully' })
  }),

  // Deployment Profiles
  http.get(`${API_BASE}/v1/deployment-profiles`, () => {
    return HttpResponse.json([mockDeploymentProfiles.valid])
  }),

  http.get(`${API_BASE}/v1/deployment-profiles/:id`, ({ params }) => {
    return HttpResponse.json(mockDeploymentProfiles.valid)
  }),

  http.post(`${API_BASE}/v1/deployment-profiles`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockDeploymentProfiles.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  // Flow Definitions
  http.get(`${API_BASE}/v1/flows`, () => {
    return HttpResponse.json([mockFlows.valid])
  }),

  http.get(`${API_BASE}/v1/flows/:id`, ({ params }) => {
    return HttpResponse.json(mockFlows.valid)
  }),

  http.post(`${API_BASE}/v1/flows`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockFlows.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  // Dashboard data
  http.get(`${API_BASE}/v1/dashboard`, () => {
    return HttpResponse.json(dashboardScenarios.fullyReady)
  }),

  // Credentials
  http.post(`${API_BASE}/v1/credentials/issue`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      credential: { id: 'cred_' + Math.random(), ...body },
      status: 'issued',
    }, { status: 201 })
  }),

  http.post(`${API_BASE}/v1/credentials/verify`, async ({ request }) => {
    return HttpResponse.json({
      valid: true,
      verification_result: {
        signature_valid: true,
        not_expired: true,
        not_revoked: true,
      },
    })
  }),

  http.get(`${API_BASE}/v1/credentials/:id`, ({ params }) => {
    return HttpResponse.json({
      id: params.id,
      status: 'issued',
      template_id: 'template_456',
      issued_at: new Date().toISOString(),
    })
  }),

  http.patch(`${API_BASE}/v1/credentials/:id/revoke`, () => {
    return HttpResponse.json({
      status: 'revoked',
      revoked_at: new Date().toISOString(),
    })
  }),

  http.post(`${API_BASE}/v1/credentials/revoke/batch`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      batch_id: 'batch_' + Math.random(),
      status: 'pending',
      credential_count: body.credential_ids?.length || 0,
    })
  }),

  http.get(`${API_BASE}/v1/credentials`, () => {
    return HttpResponse.json([])
  }),

  http.get(`${API_BASE}/v1/credentials/revocation-batches`, () => {
    return HttpResponse.json([])
  }),

  // API Keys
  http.get(`${API_BASE}/v1/organizations/:orgId/api-keys`, () => {
    return HttpResponse.json([
      {
        id: 'key_1',
        name: 'Production API',
        masked_key: 'pk_live_••••••••1234',
        scopes: ['read:credentials', 'write:credentials'],
        created_at: new Date().toISOString(),
        status: 'active',
      },
    ])
  }),

  http.post(`${API_BASE}/v1/organizations/:orgId/api-keys`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      id: 'key_new',
      name: body.name,
      key: 'pk_live_' + Math.random().toString(36).substring(7),
      masked_key: 'pk_live_••••••••' + Math.random().toString(36).substring(2, 6),
      scopes: body.scopes,
      created_at: new Date().toISOString(),
      status: 'active',
    }, { status: 201 })
  }),

  http.patch(`${API_BASE}/v1/organizations/:orgId/api-keys/:keyId/revoke`, () => {
    return HttpResponse.json({ status: 'revoked' })
  }),

  http.delete(`${API_BASE}/v1/organizations/:orgId/api-keys/:keyId`, () => {
    return HttpResponse.json({ message: 'Deleted' })
  }),

  http.get(`${API_BASE}/v1/organizations/:orgId/audit-events`, ({ params }) => {
    return HttpResponse.json({
      events: [
        {
          id: 'evt_1',
          organization_id: params.orgId,
          timestamp: new Date().toISOString(),
          actor_id: 'user_1',
          actor_type: 'user',
          action: 'credential.issued',
          resource_type: 'credential',
          resource_id: 'cred_1',
          resource_name: 'Credential cred_1',
          changes: null,
          metadata: {
            severity: 'info',
            ip_address: '127.0.0.1',
          },
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
    })
  }),

  http.get(`${API_BASE}/v1/organizations/:orgId/audit-events/:eventId`, ({ params }) => {
    return HttpResponse.json({
      id: params.eventId,
      organization_id: params.orgId,
      timestamp: new Date().toISOString(),
      actor_id: 'user_1',
      actor_type: 'user',
      action: 'credential.issued',
      resource_type: 'credential',
      resource_id: 'cred_1',
      resource_name: 'Credential cred_1',
      changes: null,
      metadata: {
        severity: 'info',
        ip_address: '127.0.0.1',
      },
    })
  }),

  // Audit Logs
  http.get(`${API_BASE}/v1/audit/events`, () => {
    return HttpResponse.json({
      events: [
        {
          id: 'evt_1',
          event_type: 'credential.issued',
          severity: 'info',
          timestamp: new Date().toISOString(),
          actor: { id: 'user_1', name: 'Test User' },
          resource: { id: 'cred_1', type: 'credential' },
          details: {},
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
    })
  }),

  // Dashboard data
  http.get(`${API_BASE}/v1/dashboard/data`, () => {
    return HttpResponse.json(dashboardScenarios.fullyReady)
  }),

  http.patch(`${API_BASE}/v1/organizations/:id/environment`, async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({ environment: body.environment })
  }),

  // Health check
  http.get(`${API_BASE}/health`, () => {
    return HttpResponse.json({ status: 'ok' })
  }),

  // Dashboard service endpoints
  http.get(`${API_BASE}/v1/organizations/:id/team/snapshot`, () => {
    return HttpResponse.json({
      members: [
        { id: 'user_1', name: 'Admin User', role: 'admin', status: 'online' },
        { id: 'user_2', name: 'Dev User', role: 'developer', status: 'online' },
        { id: 'user_3', name: 'Dev User 2', role: 'developer', status: 'offline' },
        { id: 'user_4', name: 'Operator', role: 'operator', status: 'online' },
        { id: 'user_5', name: 'Operator 2', role: 'operator', status: 'offline' },
      ],
      pending_invites: [],
      role_distribution: { admin: 1, developer: 2, operator: 2 },
    })
  }),

  http.get(`${API_BASE}/v1/organizations/:id/runtime/status`, () => {
    return HttpResponse.json({
      can_issue: true,
      can_verify: true,
      issuer_keys_valid: true,
      issuer_active: true,
      deployment_active: true,
      policy_reachable: true,
      last_issuance_timestamp: new Date().toISOString(),
      last_verification_timestamp: new Date().toISOString(),
    })
  }),

  http.get(`${API_BASE}/v1/organizations/:id/environment`, () => {
    return HttpResponse.json({ environment: 'development' })
  }),

  http.get(`${API_BASE}/v1/organizations/:id/lifecycle`, () => {
    return HttpResponse.json({
      created_at: new Date().toISOString(),
      compliance_profiles: [],
      plan_tier: 'free',
      plan_expires_at: null,
      commercial_offer: 'Developer Sandbox',
      data_retention_mode: 'standard',
      audit_retention_days: 90,
      pilot_retention: null,
    })
  }),

  http.post(`${API_BASE}/v1/organizations/:id/lifecycle/purge`, () => {
    return HttpResponse.json({
      organization_id: 'org_123',
      retention_days: 30,
      cutoff_at: new Date().toISOString(),
      purged_at: new Date().toISOString(),
      next_expiry_at: null,
      oldest_retained_record_at: null,
      tracked_scope: ['applications', 'submitted_evidence', 'issuance_transactions', 'issued_credentials', 'authorization_sessions', 'issuance_events'],
      purged_records: {
        issuance_transactions: 0,
        applications: 0,
        authorization_sessions: 0,
        issuance_events: 0,
        issued_credentials: 0,
        total: 0,
      },
    })
  }),

  // Fallback handlers for relative URLs (without base)
  // These catch requests from services that use VITE_API_URL=''
  http.get('/health', () => {
    return HttpResponse.json({ status: 'ok' })
  }),

  http.get('/v1/auth/me', () => {
    return HttpResponse.json({ authenticated: true, user: mockUsers.admin })
  }),
  
  http.get('/v1/auth/me/organizations', () => {
    return HttpResponse.json({ organizations: [mockOrganization] })
  }),

  http.get('/v1/organizations/:id/lifecycle', () => {
    return HttpResponse.json({
      created_at: new Date().toISOString(),
      compliance_profiles: [],
      plan_tier: 'free',
      plan_expires_at: null,
      commercial_offer: 'Developer Sandbox',
      data_retention_mode: 'standard',
      audit_retention_days: 90,
      pilot_retention: null,
    })
  }),

  http.post('/v1/organizations/:id/lifecycle/purge', () => {
    return HttpResponse.json({
      organization_id: 'org_123',
      retention_days: 30,
      cutoff_at: new Date().toISOString(),
      purged_at: new Date().toISOString(),
      next_expiry_at: null,
      oldest_retained_record_at: null,
      tracked_scope: ['applications', 'submitted_evidence', 'issuance_transactions', 'issued_credentials', 'authorization_sessions', 'issuance_events'],
      purged_records: {
        issuance_transactions: 0,
        applications: 0,
        authorization_sessions: 0,
        issuance_events: 0,
        issued_credentials: 0,
        total: 0,
      },
    })
  }),

  http.get('/v1/trust-profiles', () => {
    return HttpResponse.json([mockTrustProfiles.active])
  }),

  http.get('/v1/trust-profiles/:id/issuers', () => {
    return HttpResponse.json(mockTrustProfiles.active.trusted_issuers)
  }),

  http.post('/v1/trust-profiles', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTrustProfiles.active,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.patch('/v1/trust-profiles/:id', async ({ params, request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTrustProfiles.active,
      ...body,
      id: params.id,
    })
  }),

  http.post('/v1/trust-profiles/:id/issuers', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      id: 'issuer-link-created',
      status: 'active',
      ...body,
    }, { status: 201 })
  }),

  http.delete('/v1/trust-profiles/:id', () => {
    return HttpResponse.json({ message: 'Deleted' })
  }),

  http.get('/v1/credential-templates', () => {
    return HttpResponse.json([mockTemplates.valid])
  }),

  http.post('/v1/credential-templates', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockTemplates.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.get('/v1/presentation-policies', () => {
    return HttpResponse.json([mockPolicies.valid])
  }),

  http.post('/v1/presentation-policies', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockPolicies.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.patch('/v1/presentation-policies/:id', async ({ params, request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockPolicies.valid,
      ...body,
      id: params.id,
    })
  }),

  http.delete('/v1/presentation-policies/:id', () => {
    return HttpResponse.json({ message: 'Deleted' })
  }),

  http.get('/v1/deployment-profiles', () => {
    return HttpResponse.json([mockDeploymentProfiles.valid])
  }),

  http.post('/v1/deployment-profiles', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      ...mockDeploymentProfiles.valid,
      ...body,
      id: Math.floor(Math.random() * 1000),
    }, { status: 201 })
  }),

  http.get('/v1/organizations/:orgId/api-keys', () => {
    return HttpResponse.json([
      {
        id: 'key_1',
        name: 'Production API',
        masked_key: 'pk_live_\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u20221234',
        scopes: ['read:credentials', 'write:credentials'],
        created_at: new Date().toISOString(),
        status: 'active',
      },
    ])
  }),

  http.post('/v1/organizations/:orgId/api-keys', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      id: 'key_new',
      name: body.name,
      key: 'pk_live_' + Math.random().toString(36).substring(7),
      masked_key: 'pk_live_\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022' + Math.random().toString(36).substring(2, 6),
      scopes: body.scopes,
      created_at: new Date().toISOString(),
      status: 'active',
    }, { status: 201 })
  }),

  http.patch('/v1/organizations/:orgId/api-keys/:keyId/revoke', () => {
    return HttpResponse.json({ status: 'revoked' })
  }),

  http.delete('/v1/organizations/:orgId/api-keys/:keyId', () => {
    return HttpResponse.json({ message: 'Deleted' })
  }),

  http.post('/v1/credentials/issue', async ({ request }) => {
    const body = await request.json() as any
    return HttpResponse.json({
      credential: { id: 'cred_' + Math.random(), ...body },
      status: 'issued',
    }, { status: 201 })
  }),

  http.post('/v1/credentials/verify', () => {
    return HttpResponse.json({
      valid: true,
      verification_result: {
        signature_valid: true,
        not_expired: true,
        not_revoked: true,
      },
    })
  }),

  http.get('/v1/credentials/:id', ({ params }) => {
    return HttpResponse.json({
      id: params.id,
      status: 'issued',
      template_id: 'template_456',
      issued_at: new Date().toISOString(),
    })
  }),

  http.patch('/v1/credentials/:id/revoke', () => {
    return HttpResponse.json({
      status: 'revoked',
      revoked_at: new Date().toISOString(),
    })
  }),

  http.get('/v1/audit/events', () => {
    return HttpResponse.json({
      events: [
        {
          id: 'evt_1',
          event_type: 'credential.issued',
          severity: 'info',
          timestamp: new Date().toISOString(),
          actor: { id: 'user_1', name: 'Test User' },
          resource: { id: 'cred_1', type: 'credential' },
          details: {},
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
    })
  }),
]

// Scenario-specific handlers for testing different states
export const emptyOrgHandlers = [
  http.get(`${API_BASE}/v1/dashboard`, () => {
    return HttpResponse.json(dashboardScenarios.empty)
  }),
  http.get(`${API_BASE}/v1/trust-profiles`, () => {
    return HttpResponse.json([])
  }),
  http.get(`${API_BASE}/v1/credential-templates`, () => {
    return HttpResponse.json([])
  }),
  http.get(`${API_BASE}/v1/presentation-policies`, () => {
    return HttpResponse.json([])
  }),
  http.get(`${API_BASE}/v1/deployment-profiles`, () => {
    return HttpResponse.json([])
  }),
  http.get(`${API_BASE}/v1/flows`, () => {
    return HttpResponse.json([])
  }),
  http.get(`${API_BASE}/v1/organizations/:id/runtime/status`, () => {
    return HttpResponse.json({
      can_issue: false,
      can_verify: false,
      issuer_keys_valid: false,
      issuer_active: false,
      deployment_active: false,
      policy_reachable: false,
    })
  }),
  http.get(`${API_BASE}/v1/organizations/:id/team/snapshot`, () => {
    return HttpResponse.json({
      members: [],
      pending_invites: [],
      role_distribution: { admin: 0, developer: 0, operator: 0 },
    })
  }),
]

export const partiallyConfiguredHandlers = [
  http.get(`${API_BASE}/v1/dashboard`, () => {
    return HttpResponse.json(dashboardScenarios.partiallyConfigured)
  }),
  http.get(`${API_BASE}/v1/trust-profiles`, () => {
    return HttpResponse.json(dashboardScenarios.partiallyConfigured.trustProfiles)
  }),
  http.get(`${API_BASE}/v1/credential-templates`, () => {
    return HttpResponse.json(dashboardScenarios.partiallyConfigured.templates)
  }),
]

export const errorHandlers = [
  http.get(`${API_BASE}/v1/trust-profiles`, () => {
    return HttpResponse.json(mockErrors.serverError, { status: 500 })
  }),
  http.post(`${API_BASE}/v1/trust-profiles`, () => {
    return HttpResponse.json(mockErrors.validation, { status: 400 })
  }),
]
