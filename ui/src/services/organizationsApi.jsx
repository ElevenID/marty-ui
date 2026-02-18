/**
 * Organizations Service
 *
 * API client functions for organization management.
 * Uses the centralized api.js service for consistent error handling and retry logic.
 */
import { get, post, patch, del, getErrorMessage } from './api';
import { buildDefinedQueryString, buildTruthyQueryString, withQuery } from './queryUtils';

const BASE_PATH = '/v1/organizations';

/**
 * Get organization details
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Organization object with details
 */
export async function getOrganization(organizationId) {
  return get(`${BASE_PATH}/${organizationId}`);
}

/**
 * Create a new organization
 * @param {Object} data - Organization data
 * @param {string} data.name - Organization name (unique identifier)
 * @param {string} data.display_name - Display name
 * @param {string} data.org_type - Organization type (e.g., 'enterprise', 'startup')
 * @param {string} [data.description] - Optional description
 * @param {string} [data.contact_email] - Optional contact email
 * @returns {Promise<Object>} - Created organization object
 */
export async function createOrganization(data) {
  return post(BASE_PATH, data);
}

/**
 * List all organizations (admin only)
 * @param {Object} options - Filter options
 * @param {number} options.limit - Max number of records (default: 100)
 * @param {number} options.offset - Pagination offset (default: 0)
 * @returns {Promise<Array>} - Array of organization objects
 */
export async function listOrganizations({ limit = 100, offset = 0 } = {}) {
  const queryString = buildDefinedQueryString({ limit, offset });
  return get(withQuery(BASE_PATH, queryString));
}

/**
 * Get current user's organizations with membership details
 * @returns {Promise<Array>} - Array of organizations with membership info
 */
export async function getMyOrganizations() {
  return get(`${BASE_PATH}/mine`);
}

/**
 * Discover publicly available organizations
 * @param {Object} options - Filter options
 * @param {string} options.search - Search by name or display name
 * @param {string} options.orgType - Filter by organization type
 * @param {string} options.joinMechanism - Filter by join mechanism
 * @param {number} options.limit - Max number of records (default: 100)
 * @param {number} options.offset - Pagination offset (default: 0)
 * @returns {Promise<Array>} - Array of discoverable organization objects
 */
export async function discoverOrganizations({ search, orgType, joinMechanism, limit = 100, offset = 0 } = {}) {
  const queryString = buildTruthyQueryString({
    search,
    org_type: orgType,
    join_mechanism: joinMechanism,
    limit,
    offset,
  });
  return get(withQuery(`${BASE_PATH}/discover`, queryString));
}

/**
 * Join an organization using a join code
 * @param {string} code - 8-character join code
 * @returns {Promise<Object>} - Organization and membership details
 */
export async function joinByCode(code) {
  return post(`${BASE_PATH}/join/code`, { code });
}

/**
 * Validate a join/invitation code without joining.
 * Public endpoint.
 * @param {string} code - Join/invitation code
 * @returns {Promise<Object>} - Validation result
 */
export async function validateJoinCode(code) {
  const encoded = encodeURIComponent(code);
  return get(`${BASE_PATH}/join/code/validate?code=${encoded}`);
}

/**
 * Join/request to join an organization directly by ID.
 * Works for organizations with open join enabled.
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Organization and membership details
 */
export async function joinOrganization(organizationId) {
  return post(`${BASE_PATH}/${organizationId}/join`, {});
}

/**
 * Validate an invitation token.
 * Public endpoint (no auth required).
 * @param {string} token - Invitation token/code
 * @returns {Promise<Object>} - Validation details
 */
export async function validateOrganizationInvitation(token) {
  const encoded = encodeURIComponent(token);
  try {
    return await get(`${BASE_PATH}/invitations/validate?token=${encoded}`);
  } catch (error) {
    const status = error?.status;
    // Compatibility fallback for environments still serving legacy invite endpoints
    if (status === 404 || status === 502 || status === 503 || status === 504) {
      try {
        return await validateJoinCode(token);
      } catch {
        try {
          return await get(`/api/invitations/validate?token=${encoded}`);
        } catch {
          return get(`/api/onboarding/invitations/validate?token=${encoded}`);
        }
      }
    }
    throw error;
  }
}

/**
 * Accept an invitation token.
 * Requires authenticated session.
 * @param {string} token - Invitation token/code
 * @returns {Promise<Object>} - Acceptance details
 */
export async function acceptOrganizationInvitation(token) {
  try {
    return await post(`${BASE_PATH}/invitations/accept`, { token });
  } catch (error) {
    const status = error?.status;
    // Compatibility fallback for environments still serving legacy invite endpoints
    if (status === 404 || status === 502 || status === 503 || status === 504) {
      try {
        return await joinByCode(token);
      } catch {
        try {
          return await post('/api/invitations/accept', { token });
        } catch {
          return post('/api/onboarding/invitations/accept', { token });
        }
      }
    }
    throw error;
  }
}

/**
 * Update organization details
 * @param {string} organizationId - Organization ID
 * @param {Object} updates - Fields to update
 * @param {string} updates.name - Organization name
 * @param {string} updates.logoUrl - Logo URL
 * @param {string} updates.websiteUrl - Website URL
 * @param {string} updates.contactEmail - Contact email
 * @returns {Promise<Object>} - Updated organization object
 */
export async function updateOrganization(organizationId, updates) {
  const body = {};
  if (updates.name !== undefined) body.name = updates.name;
  if (updates.logoUrl !== undefined) body.logo_url = updates.logoUrl;
  if (updates.websiteUrl !== undefined) body.website_url = updates.websiteUrl;
  if (updates.contactEmail !== undefined) body.contact_email = updates.contactEmail;
  return patch(`${BASE_PATH}/${organizationId}`, body);
}

/**
 * Get organization members
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} - Array of member objects with roles
 */
export async function getOrganizationMembers(organizationId) {
  const response = await get(`${BASE_PATH}/${organizationId}/members`);
  return response?.members || [];
}

/**
 * Add a member to an organization
 * @param {string} organizationId - Organization ID
 * @param {Object} memberData - Member data
 * @param {string} memberData.userId - User ID to add
 * @param {string} memberData.role - Role ('owner', 'admin', 'member')
 * @returns {Promise<Object>} - Created member object
 */
export async function addOrganizationMember(organizationId, { userId, role }) {
  return post(`${BASE_PATH}/${organizationId}/members`, {
    user_id: userId,
    role,
  });
}

/**
 * Update a member's role
 * @param {string} organizationId - Organization ID
 * @param {string} userId - User ID
 * @param {string} role - New role ('owner', 'admin', 'member')
 * @returns {Promise<Object>} - Updated member object
 */
export async function updateOrganizationMember(organizationId, userId, role) {
  return patch(`${BASE_PATH}/${organizationId}/members/${userId}`, { role });
}

/**
 * Remove a member from an organization
 * @param {string} organizationId - Organization ID
 * @param {string} userId - User ID to remove
 * @returns {Promise<null>} - Empty response on success
 */
export async function removeOrganizationMember(organizationId, userId) {
  return del(`${BASE_PATH}/${organizationId}/members/${userId}`);
}

/**
 * Get organization subscription details
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Subscription details with tier and limits
 */
export async function getOrganizationSubscription(organizationId) {
  return get(`${BASE_PATH}/${organizationId}/subscription`);
}

/**
 * Get organization usage statistics
 * @param {string} organizationId - Organization ID
 * @param {Object} options - Query options
 * @param {string} options.startDate - Start date ISO string
 * @param {string} options.endDate - End date ISO string
 * @returns {Promise<Object>} - Usage statistics
 */
export async function getOrganizationUsage(organizationId, { startDate, endDate } = {}) {
  const queryString = buildTruthyQueryString({
    start_date: startDate,
    end_date: endDate,
  });
  return get(withQuery(`${BASE_PATH}/${organizationId}/usage`, queryString));
}

/**
 * Get organization invitations
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} - Array of invitation objects
 */
export async function getOrganizationInvitations(organizationId) {
  const response = await get(`${BASE_PATH}/${organizationId}/invitations`);
  return response?.invitations || [];
}

/**
 * Create an organization invitation
 * @param {string} organizationId - Organization ID
 * @param {Object} invitationData - Invitation data
 * @param {string} invitationData.email - Email to invite
 * @param {string} invitationData.role - Role for the invited user
 * @returns {Promise<Object>} - Created invitation with invite code
 */
export async function createOrganizationInvitation(organizationId, { email, role }) {
  return post(`${BASE_PATH}/${organizationId}/invitations`, {
    email,
    role,
  });
}

/**
 * Cancel an organization invitation
 * @param {string} organizationId - Organization ID
 * @param {string} invitationId - Invitation ID
 * @returns {Promise<null>} - Empty response on success
 */
export async function cancelOrganizationInvitation(organizationId, invitationId) {
  return del(`${BASE_PATH}/${organizationId}/invitations/${invitationId}`);
}

/**
 * Get organization defaults
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Organization defaults
 */
export async function getOrganizationDefaults(organizationId) {
  return get(`${BASE_PATH}/${organizationId}/defaults`);
}

/**
 * Update organization defaults
 * @param {string} organizationId - Organization ID
 * @param {Object} defaults - Default resource IDs
 * @param {string} defaults.default_trust_profile_id - Default trust profile
 * @param {string} defaults.default_policy_id - Default presentation policy
 * @param {string} defaults.default_template_id - Default credential template
 * @returns {Promise<Object>} - Updated defaults
 */
export async function updateOrganizationDefaults(organizationId, defaults) {
  return patch(`${BASE_PATH}/${organizationId}/defaults`, defaults);
}

// Re-export getErrorMessage for convenience
export { getErrorMessage };

export default {
  getOrganization,
  createOrganization,
  listOrganizations,
  getMyOrganizations,
  discoverOrganizations,
  validateJoinCode,
  joinByCode,
  joinOrganization,
  validateOrganizationInvitation,
  acceptOrganizationInvitation,
  updateOrganization,
  getOrganizationMembers,
  addOrganizationMember,
  updateOrganizationMember,
  removeOrganizationMember,
  getOrganizationSubscription,
  getOrganizationUsage,
  getOrganizationInvitations,
  createOrganizationInvitation,
  cancelOrganizationInvitation,
  getOrganizationDefaults,
  updateOrganizationDefaults,
  getErrorMessage,
};
