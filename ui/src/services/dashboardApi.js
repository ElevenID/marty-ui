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
import { post } from './api';
import { getCriticalEvents as getAuditCriticalEvents } from './auditApi';

const BASE_PATH = '/v1/organizations';

function shouldLogDashboardError(error) {
  return error?.status !== 403;
}

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
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch team snapshot:', getErrorMessage(error));
    }
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
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch runtime status:', getErrorMessage(error));
    }
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
    return await getAuditCriticalEvents(organizationId);
  } catch (error) {
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch critical events:', getErrorMessage(error));
    }
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
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch organization environment:', getErrorMessage(error));
    }
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
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch API integration status:', getErrorMessage(error));
    }
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
      planTier: response?.plan_tier || 'free',
      planExpiresAt: response?.plan_expires_at || null,
      commercialOffer: response?.commercial_offer || 'Developer Sandbox',
      dataRetentionMode: response?.data_retention_mode || 'standard',
      auditRetentionDays: response?.audit_retention_days || 90,
      pilotRetention: response?.pilot_retention ? {
        enabled: Boolean(response?.pilot_retention?.enabled),
        windowDays: response?.pilot_retention?.window_days || 30,
        scopeSummary: response?.pilot_retention?.scope_summary || '',
        scopeItems: response?.pilot_retention?.scope_items || [],
        accessBehavior: response?.pilot_retention?.access_behavior || '',
        lastPurgedAt: response?.pilot_retention?.last_purged_at || null,
        cutoffAt: response?.pilot_retention?.cutoff_at || null,
        nextExpiryAt: response?.pilot_retention?.next_expiry_at || null,
        oldestRetainedRecordAt: response?.pilot_retention?.oldest_retained_record_at || null,
        trackedScope: response?.pilot_retention?.tracked_scope || [],
        eligibleForPurge: {
          issuanceTransactions: response?.pilot_retention?.eligible_for_purge?.issuance_transactions || 0,
          applications: response?.pilot_retention?.eligible_for_purge?.applications || 0,
          authorizationSessions: response?.pilot_retention?.eligible_for_purge?.authorization_sessions || 0,
          issuanceEvents: response?.pilot_retention?.eligible_for_purge?.issuance_events || 0,
          issuedCredentials: response?.pilot_retention?.eligible_for_purge?.issued_credentials || 0,
          total: response?.pilot_retention?.eligible_for_purge?.total || 0,
        },
      } : null,
    };
  } catch (error) {
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch organization lifecycle:', getErrorMessage(error));
    }
    return {
      createdAt: null,
      complianceProfiles: [],
      planTier: 'free',
      planExpiresAt: null,
      commercialOffer: 'Developer Sandbox',
      dataRetentionMode: 'standard',
      auditRetentionDays: 90,
      pilotRetention: null,
    };
  }
}

/**
 * Run a Hosted Pilot purge for the organization.
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Purge result
 */
export async function runHostedPilotPurge(organizationId) {
  try {
    const response = await post(`${BASE_PATH}/${organizationId}/lifecycle/purge`);
    return {
      organizationId: response?.organization_id || organizationId,
      retentionDays: response?.retention_days || 30,
      purgedAt: response?.purged_at || null,
      nextExpiryAt: response?.next_expiry_at || null,
      oldestRetainedRecordAt: response?.oldest_retained_record_at || null,
      trackedScope: response?.tracked_scope || [],
      purgedRecords: {
        issuanceTransactions: response?.purged_records?.issuance_transactions || 0,
        applications: response?.purged_records?.applications || 0,
        authorizationSessions: response?.purged_records?.authorization_sessions || 0,
        issuanceEvents: response?.purged_records?.issuance_events || 0,
        issuedCredentials: response?.purged_records?.issued_credentials || 0,
        total: response?.purged_records?.total || 0,
      },
    };
  } catch (error) {
    console.error('Failed to run Hosted Pilot purge:', getErrorMessage(error));
    throw error;
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
    if (error?.status !== 403) {
      console.error('Failed to fetch applicant stats:', getErrorMessage(error));
    }
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
    if (shouldLogDashboardError(error)) {
      console.error('Failed to fetch integration info:', getErrorMessage(error));
    }
    return {
      orgId: organizationId,
      baseUrl: window.location.origin + '/api',
      exampleRequest: null,
    };
  }
}

