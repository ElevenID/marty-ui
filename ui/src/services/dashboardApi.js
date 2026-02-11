/**
 * Dashboard Data Service
 *
 * API client functions for dashboard-specific data:
 * - Team/Member information
 * - Runtime operational status
 * - Critical events
 * - Environment settings
 */
import { get, getErrorMessage } from './api';

const BASE_PATH = '/v1/organizations';

/**
 * Get team snapshot data for dashboard
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Team data with members, roles, and invites
 */
export async function getTeamSnapshot(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/team/snapshot`);
    return {
      members: response?.members || [],
      pendingInvites: response?.pending_invites || [],
      roleDistribution: response?.role_distribution || {
        admin: 0,
        developer: 0,
        operator: 0,
      },
    };
  } catch (error) {
    console.error('Failed to fetch team snapshot:', getErrorMessage(error));
    // Return empty data on failure
    return {
      members: [],
      pendingInvites: [],
      roleDistribution: { admin: 0, developer: 0, operator: 0 },
    };
  }
}

/**
 * Get runtime operational status
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Runtime status with operational readiness
 */
export async function getRuntimeStatus(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/runtime/status`);
    return {
      canIssue: response?.can_issue || false,
      canVerify: response?.can_verify || false,
      issuerKeysValid: response?.issuer_keys_valid || false,
      issuerActive: response?.issuer_active || false,
      deploymentActive: response?.deployment_active || false,
      policyReachable: response?.policy_reachable || false,
      lastIssuance: response?.last_issuance_timestamp || null,
      lastVerification: response?.last_verification_timestamp || null,
    };
  } catch (error) {
    console.error('Failed to fetch runtime status:', getErrorMessage(error));
    // Return safe defaults on failure
    return {
      canIssue: false,
      canVerify: false,
      issuerKeysValid: false,
      issuerActive: false,
      deploymentActive: false,
      policyReachable: false,
      lastIssuance: null,
      lastVerification: null,
    };
  }
}

/**
 * Get critical events (last 24h)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} Critical events array
 */
export async function getCriticalEvents(organizationId) {
  try {
    const params = new URLSearchParams();
    params.append('severity', 'error,warning');
    params.append('hours', '24');
    params.append('limit', '10');
    
    const response = await get(`${BASE_PATH}/${organizationId}/audit/critical?${params.toString()}`);
    return response?.events || [];
  } catch (error) {
    console.error('Failed to fetch critical events:', getErrorMessage(error));
    return [];
  }
}

/**
 * Get organization environment setting
 * @param {string} organizationId - Organization ID
 * @returns {Promise<string>} Environment ('development', 'staging', 'production')
 */
export async function getOrganizationEnvironment(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/environment`);
    return response?.environment || 'development';
  } catch (error) {
    console.error('Failed to fetch organization environment:', getErrorMessage(error));
    return 'development';
  }
}

/**
 * Update organization environment
 * @param {string} organizationId - Organization ID
 * @param {string} environment - New environment ('development', 'staging', 'production')
 * @returns {Promise<Object>} Updated environment setting
 */
export async function updateOrganizationEnvironment(organizationId, environment) {
  try {
    const response = await fetch(`/api${BASE_PATH}/${organizationId}/environment`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ environment }),
    });

    if (!response.ok) {
      throw new Error(`Failed to update environment: ${response.statusText}`);
    }

    return response.json();
  } catch (error) {
    console.error('Failed to update organization environment:', getErrorMessage(error));
    throw error;
  }
}

/**
 * Get API integration status
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} API integration status
 */
export async function getApiIntegrationStatus(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/api/status`);
    return {
      activeApiKeys: response?.active_api_keys || 0,
      lastApiCall: response?.last_api_call_timestamp || null,
      webhookDeliveryHealth: response?.webhook_delivery_health || {
        success: 0,
        failed: 0,
      },
    };
  } catch (error) {
    console.error('Failed to fetch API integration status:', getErrorMessage(error));
    return {
      activeApiKeys: 0,
      lastApiCall: null,
      webhookDeliveryHealth: { success: 0, failed: 0 },
    };
  }
}

/**
 * Get organization lifecycle metadata
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Lifecycle metadata
 */
export async function getOrganizationLifecycle(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/lifecycle`);
    return {
      createdAt: response?.created_at || null,
      complianceProfiles: response?.compliance_profiles || [],
      dataRetentionMode: response?.data_retention_mode || 'standard',
      auditRetentionDays: response?.audit_retention_days || 90,
    };
  } catch (error) {
    console.error('Failed to fetch organization lifecycle:', getErrorMessage(error));
    return {
      createdAt: null,
      complianceProfiles: [],
      dataRetentionMode: 'standard',
      auditRetentionDays: 90,
    };
  }
}

/**
 * Get applicant statistics for dashboard
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Applicant stats (pending, approved, issuable)
 */
export async function getApplicantStats(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/dashboard/applicant-stats`);
    return {
      pending: response?.pending || 0,
      approved: response?.approved || 0,
      issuable: response?.issuable || 0,
      total: response?.total || 0,
    };
  } catch (error) {
    console.error('Failed to fetch applicant stats:', getErrorMessage(error));
    return {
      pending: 0,
      approved: 0,
      issuable: 0,
      total: 0,
    };
  }
}

/**
 * Get organization integration info for developer quick start
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Integration info (org_id, base_url, example_request)
 */
export async function getOrganizationIntegrationInfo(organizationId) {
  try {
    const response = await get(`${BASE_PATH}/${organizationId}/integration-info`);
    return {
      orgId: response?.org_id || organizationId,
      baseUrl: response?.base_url || window.location.origin + '/api',
      exampleRequest: response?.example_request || null,
    };
  } catch (error) {
    console.error('Failed to fetch integration info:', getErrorMessage(error));
    return {
      orgId: organizationId,
      baseUrl: window.location.origin + '/api',
      exampleRequest: null,
    };
  }
}

