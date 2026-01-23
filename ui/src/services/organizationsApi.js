/**
 * Organizations Service
 *
 * API client functions for organization management.
 * Uses the centralized api.js service for consistent error handling and retry logic.
 */
import { get, post, patch, del, getErrorMessage } from './api';

const BASE_PATH = '/api/organizations';

/**
 * Get organization details
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Organization object with details
 */
export async function getOrganization(organizationId) {
  return get(`${BASE_PATH}/${organizationId}`);
}

/**
 * List all organizations (admin only)
 * @param {Object} options - Filter options
 * @param {number} options.limit - Max number of records (default: 100)
 * @param {number} options.offset - Pagination offset (default: 0)
 * @returns {Promise<Array>} - Array of organization objects
 */
export async function listOrganizations({ limit = 100, offset = 0 } = {}) {
  const params = new URLSearchParams();
  params.append('limit', limit.toString());
  params.append('offset', offset.toString());
  return get(`${BASE_PATH}?${params.toString()}`);
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
  const params = new URLSearchParams();
  if (startDate) params.append('start_date', startDate);
  if (endDate) params.append('end_date', endDate);
  const queryString = params.toString();
  const url = `${BASE_PATH}/${organizationId}/usage${queryString ? `?${queryString}` : ''}`;
  return get(url);
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

// Re-export getErrorMessage for convenience
export { getErrorMessage };

export default {
  getOrganization,
  listOrganizations,
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
  getErrorMessage,
};
