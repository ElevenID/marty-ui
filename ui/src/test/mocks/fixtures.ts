/**
 * Test Fixtures
 * 
 * Standardized mock data scenarios for consistent testing:
 * - Empty org (no profiles)
 * - Partially configured (blocked states)
 * - Fully configured (ready)
 * - API errors
 */

// User fixtures
export const mockUsers = {
  admin: {
    id: 1,
    username: 'admin@example.com',
    email: 'admin@example.com',
    user_type: 'administrator',
    organization_id: 1,
    first_name: 'Admin',
    last_name: 'User',
    is_active: true,
  },
  vendor: {
    id: 2,
    username: 'vendor@example.com',
    email: 'vendor@example.com',
    user_type: 'vendor',
    organization_id: 1,
    first_name: 'Vendor',
    last_name: 'User',
    is_active: true,
  },
  applicant: {
    id: 3,
    username: 'applicant@example.com',
    email: 'applicant@example.com',
    user_type: 'applicant',
    organization_id: 1,
    first_name: 'Applicant',
    last_name: 'User',
    is_active: true,
  },
}

// Organization fixture
export const mockOrganization = {
  id: 1,
  name: 'Test Organization',
  description: 'Test organization for unit tests',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
}

// Trust Profile fixtures
export const mockTrustProfiles = {
  active: {
    id: 1,
    name: 'Test Trust Profile',
    description: 'Active trust profile',
    status: 'active',
    trust_list_url: 'https://example.com/trust-list',
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  inactive: {
    id: 2,
    name: 'Inactive Trust Profile',
    description: 'Inactive trust profile',
    status: 'inactive',
    trust_list_url: 'https://example.com/trust-list',
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
}

// Credential Template fixtures
export const mockTemplates = {
  valid: {
    id: 1,
    name: 'mDL Template',
    description: 'Mobile Driver License template',
    doctype: 'org.iso.18013.5.1.mDL',
    namespace: 'org.iso.18013.5.1',
    status: 'active',
    artifacts_status: 'valid',
    trust_profile_id: 1,
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    fields: [],
  },
  missingArtifacts: {
    id: 2,
    name: 'Incomplete Template',
    description: 'Template with missing artifacts',
    doctype: 'com.example.test',
    namespace: 'com.example',
    status: 'active',
    artifacts_status: 'missing',
    trust_profile_id: 1,
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    fields: [],
  },
}

// Presentation Policy fixtures
export const mockPolicies = {
  valid: {
    id: 1,
    name: 'Age Verification',
    description: 'Verify age over 21',
    status: 'active',
    credential_template_id: 1,
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    conditions: [],
  },
}

// Deployment Profile fixtures
export const mockDeploymentProfiles = {
  valid: {
    id: 1,
    name: 'Production Deployment',
    description: 'Production deployment profile',
    status: 'active',
    environment: 'production',
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
}

// Flow Definition fixtures
export const mockFlows = {
  valid: {
    id: 1,
    name: 'Onboarding Flow',
    description: 'User onboarding flow',
    status: 'active',
    steps: [],
    trust_profile_id: 1,
    presentation_policy_id: 1,
    deployment_profile_id: 1,
    organization_id: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
}

// Dashboard data scenarios
export const dashboardScenarios = {
  empty: {
    trustProfiles: [],
    templates: [],
    policies: [],
    deploymentProfiles: [],
    flows: [],
    readiness: {
      trustProfile: { state: 'NOT_READY', count: 0 },
      credentialTemplate: { state: 'NOT_READY', count: 0 },
      presentationPolicy: { state: 'NOT_READY', count: 0 },
      deploymentProfile: { state: 'NOT_READY', count: 0 },
      flow: { state: 'NOT_READY', count: 0 },
    },
    runtimeStatus: {
      canIssue: false,
      canVerify: false,
      hasActiveDeployments: false,
    },
    systemHealth: {
      api: 'healthy',
      database: 'healthy',
      redis: 'healthy',
    },
    criticalEvents: [],
    teamData: {
      totalMembers: 1,
      onlineMembers: 1,
    },
    environment: 'development',
  },
  partiallyConfigured: {
    trustProfiles: [mockTrustProfiles.active],
    templates: [mockTemplates.missingArtifacts],
    policies: [],
    deploymentProfiles: [],
    flows: [],
    readiness: {
      trustProfile: { state: 'READY', count: 1 },
      credentialTemplate: { state: 'BLOCKED', count: 1 },
      presentationPolicy: { state: 'NOT_READY', count: 0 },
      deploymentProfile: { state: 'NOT_READY', count: 0 },
      flow: { state: 'NOT_READY', count: 0 },
    },
    runtimeStatus: {
      canIssue: false,
      canVerify: false,
      hasActiveDeployments: false,
    },
    systemHealth: {
      api: 'healthy',
      database: 'healthy',
      redis: 'healthy',
    },
    criticalEvents: [],
    teamData: {
      totalMembers: 3,
      onlineMembers: 2,
    },
    environment: 'development',
  },
  fullyReady: {
    trustProfiles: [mockTrustProfiles.active],
    templates: [mockTemplates.valid],
    policies: [mockPolicies.valid],
    deploymentProfiles: [mockDeploymentProfiles.valid],
    flows: [mockFlows.valid],
    readiness: {
      trustProfile: { state: 'READY', count: 1 },
      credentialTemplate: { state: 'READY', count: 1 },
      presentationPolicy: { state: 'READY', count: 1 },
      deploymentProfile: { state: 'READY', count: 1 },
      flow: { state: 'READY', count: 1 },
    },
    runtimeStatus: {
      canIssue: true,
      canVerify: true,
      hasActiveDeployments: true,
    },
    systemHealth: {
      api: 'healthy',
      database: 'healthy',
      redis: 'healthy',
    },
    criticalEvents: [],
    recentActivity: [
      {
        id: 1,
        type: 'credential.issued',
        message: 'Credential issued',
        timestamp: new Date().toISOString(),
      },
    ],
    teamData: {
      totalMembers: 5,
      onlineMembers: 3,
    },
    environment: 'production',
  },
}

// API error responses
export const mockErrors = {
  unauthorized: {
    error: {
      code: 'UNAUTHORIZED',
      message: 'Authentication required',
      status: 401,
    },
  },
  forbidden: {
    error: {
      code: 'FORBIDDEN',
      message: 'Insufficient permissions',
      status: 403,
    },
  },
  notFound: {
    error: {
      code: 'NOT_FOUND',
      message: 'Resource not found',
      status: 404,
    },
  },
  validation: {
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      status: 400,
      details: {
        field: 'name',
        message: 'Name is required',
      },
    },
  },
  serverError: {
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Internal server error',
      status: 500,
    },
  },
}
