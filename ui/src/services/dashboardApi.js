/**
 * Dashboard Data Service
 *
 * API client functions for dashboard-specific data:
 * - Team/Member information
 * - Runtime operational status
 * - Critical events
 * - Environment settings
 */
import { getErrorMessage, getWithRetryConfig, patch, post } from './api';
import { getCriticalEvents as getAuditCriticalEvents } from './auditApi';
import { requireOrganizationId } from './queryUtils';

const BASE_PATH = '/v1/organizations';
const DASHBOARD_RETRY_CONFIG = { maxRetries: 0 };
const SHOULD_LOG_DASHBOARD_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function getDashboard(endpoint) {
  return getWithRetryConfig(endpoint, {}, DASHBOARD_RETRY_CONFIG);
}

function logDashboardError(message, error) {
  if (SHOULD_LOG_DASHBOARD_DIAGNOSTICS) {
    console.error(message, getErrorMessage(error));
  }
}

function createIncompleteDashboardPayloadError(sourceName, missingFields) {
  const fieldList = missingFields.length ? ` Missing fields: ${missingFields.join(', ')}.` : '';
  const error = new Error(`${sourceName} returned an incomplete response.${fieldList}`);
  error.code = 'DASHBOARD_PAYLOAD_INCOMPLETE';
  error.status = 502;
  error.messageId = null;
  return error;
}

function requireDashboardFields(response, sourceName, requiredFields) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    throw createIncompleteDashboardPayloadError(sourceName, requiredFields);
  }

  const missingFields = requiredFields.filter(
    (field) => !Object.prototype.hasOwnProperty.call(response, field)
  );
  if (missingFields.length > 0) {
    throw createIncompleteDashboardPayloadError(sourceName, missingFields);
  }

  return response;
}

/**
 * Get team snapshot data for dashboard
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Team data with members, roles, and invites
 */
export async function getTeamSnapshot(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading team snapshot');
  const response = requireDashboardFields(
    await getDashboard(`${BASE_PATH}/${encodeURIComponent(orgId)}/team/snapshot`),
    'Team snapshot',
    ['members', 'pending_invites', 'role_distribution']
  );
  return {
    members: Array.isArray(response.members) ? response.members : [],
    pendingInvites: Array.isArray(response.pending_invites) ? response.pending_invites : [],
    roleDistribution: response.role_distribution && typeof response.role_distribution === 'object'
      ? response.role_distribution
      : {},
  };
}

/**
 * Get runtime operational status
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Runtime status with operational readiness
 */
export async function getRuntimeStatus(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading runtime status');
  const response = requireDashboardFields(
    await getDashboard(`${BASE_PATH}/${encodeURIComponent(orgId)}/runtime/status`),
    'Runtime status',
    [
      'can_issue',
      'can_verify',
      'issuer_keys_valid',
      'issuer_active',
      'deployment_active',
      'policy_reachable',
    ]
  );
  return {
    canIssue: Boolean(response.can_issue),
    canVerify: Boolean(response.can_verify),
    issuerKeysValid: Boolean(response.issuer_keys_valid),
    issuerActive: Boolean(response.issuer_active),
    deploymentActive: Boolean(response.deployment_active),
    policyReachable: Boolean(response.policy_reachable),
    lastIssuance: response.last_issuance_timestamp || null,
    lastVerification: response.last_verification_timestamp || null,
  };
}

/**
 * Get critical events (last 24h)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} Critical events array
 */
export async function getCriticalEvents(organizationId) {
  return await getAuditCriticalEvents(requireOrganizationId(organizationId, 'loading critical events'));
}

/**
 * Get organization environment setting
 * @param {string} organizationId - Organization ID
 * @returns {Promise<string>} Environment ('development', 'staging', 'production')
 */
export async function getOrganizationEnvironment(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading organization environment');
  const response = requireDashboardFields(
    await getDashboard(`${BASE_PATH}/${encodeURIComponent(orgId)}/environment`),
    'Organization environment',
    ['environment']
  );
  return response.environment || null;
}

/**
 * Update organization environment
 * @param {string} organizationId - Organization ID
 * @param {string} environment - New environment ('development', 'staging', 'production')
 * @returns {Promise<Object>} Updated environment setting
 */
export async function updateOrganizationEnvironment(organizationId, environment) {
  const orgId = requireOrganizationId(organizationId, 'updating organization environment');
  try {
    return await patch(`${BASE_PATH}/${encodeURIComponent(orgId)}/environment`, { environment });
  } catch (error) {
    logDashboardError('Failed to update organization environment:', error);
    throw error;
  }
}

/**
 * Get organization lifecycle metadata
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Lifecycle metadata
 */
export async function getOrganizationLifecycle(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading organization lifecycle');
  const response = await getDashboard(`${BASE_PATH}/${encodeURIComponent(orgId)}/lifecycle`);
  return {
    createdAt: response?.created_at || null,
    complianceProfiles: response?.compliance_profiles || [],
    planTier: response?.plan_tier || null,
    planExpiresAt: response?.plan_expires_at || null,
    commercialOffer: response?.commercial_offer || null,
    dataRetentionMode: response?.data_retention_mode || null,
    auditRetentionDays: response?.audit_retention_days ?? null,
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
}

/**
 * Run a Hosted Pilot purge for the organization.
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Purge result
 */
export async function runHostedPilotPurge(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'running Hosted Pilot purge');
  try {
    const response = await post(`${BASE_PATH}/${encodeURIComponent(orgId)}/lifecycle/purge`);
    const normalizedResponse = requireDashboardFields(
      response,
      'Hosted Pilot purge',
      ['purged_records']
    );
    return {
      organizationId: normalizedResponse.organization_id || orgId,
      retentionDays: normalizedResponse.retention_days ?? 30,
      purgedAt: normalizedResponse.purged_at || null,
      nextExpiryAt: normalizedResponse.next_expiry_at || null,
      oldestRetainedRecordAt: normalizedResponse.oldest_retained_record_at || null,
      trackedScope: normalizedResponse.tracked_scope || [],
      purgedRecords: {
        issuanceTransactions: normalizedResponse.purged_records?.issuance_transactions ?? 0,
        applications: normalizedResponse.purged_records?.applications ?? 0,
        authorizationSessions: normalizedResponse.purged_records?.authorization_sessions ?? 0,
        issuanceEvents: normalizedResponse.purged_records?.issuance_events ?? 0,
        issuedCredentials: normalizedResponse.purged_records?.issued_credentials ?? 0,
        total: normalizedResponse.purged_records?.total ?? 0,
      },
    };
  } catch (error) {
    logDashboardError('Failed to run Hosted Pilot purge:', error);
    throw error;
  }
}

/**
 * Get applicant statistics for dashboard
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Applicant stats (pending, approved, issuable)
 */
export async function getApplicantStats(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading applicant stats');
  const response = requireDashboardFields(
    await getDashboard(`${BASE_PATH}/${encodeURIComponent(orgId)}/dashboard/applicant-stats`),
    'Applicant stats',
    ['pending', 'approved', 'issuable', 'total']
  );
  return {
    pending: response.pending ?? 0,
    approved: response.approved ?? 0,
    issuable: response.issuable ?? 0,
    total: response.total ?? 0,
  };
}

/**
 * Get organization integration info for developer quick start
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Integration info (org_id, base_url, example_request)
 */
export async function getOrganizationIntegrationInfo(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading integration metadata');
  const response = requireDashboardFields(
    await getDashboard(`${BASE_PATH}/${encodeURIComponent(orgId)}/integration-info`),
    'Integration metadata',
    ['org_id', 'base_url', 'example_request']
  );
  return {
    orgId: response.org_id,
    baseUrl: response.base_url,
    exampleRequest: response.example_request,
  };
}
