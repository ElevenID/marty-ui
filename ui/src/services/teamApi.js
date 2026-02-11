/**
 * Team Management API Service
 * 
 * Manages team members, invites, and role assignments.
 */

import { get, post, patch, del } from './api';

const BASE_PATH = '/v1/teams';

/**
 * List team members
 * @param {string} organizationId - Organization ID
 * @param {Object} filters - Query filters
 * @param {string} filters.role - Filter by role
 * @param {string} filters.status - Filter by status
 * @returns {Promise<Array>} List of team members
 */
export async function listMembers(organizationId, filters = {}) {
  const params = new URLSearchParams();
  if (filters.role) params.append('role', filters.role);
  if (filters.status) params.append('status', filters.status);
  
  const queryString = params.toString();
  const path = `/v1/organizations/${organizationId}/members`;
  return get(queryString ? `${path}?${queryString}` : path);
}

/**
 * Get team member by ID
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @returns {Promise<Object>} Team member details
 */
export async function getMember(organizationId, memberId) {
  return get(`/v1/organizations/${organizationId}/members/${memberId}`);
}

/**
 * Invite team member
 * @param {string} organizationId - Organization ID
 * @param {Object} invite - Invite data
 * @param {string} invite.email - Invitee email
 * @param {string} invite.role - Role to assign (admin, dev, operator)
 * @param {string} invite.message - Optional personal message
 * @returns {Promise<Object>} Created invite
 */
export async function inviteMember(organizationId, invite) {
  return post(`/v1/organizations/${organizationId}/invites`, invite);
}

/**
 * List pending invites
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} List of pending invites
 */
export async function listInvites(organizationId) {
  return get(`/v1/organizations/${organizationId}/invites`);
}

/**
 * Resend invite
 * @param {string} organizationId - Organization ID
 * @param {string} inviteId - Invite ID
 * @returns {Promise<Object>} Updated invite
 */
export async function resendInvite(organizationId, inviteId) {
  return post(`/v1/organizations/${organizationId}/invites/${inviteId}/resend`, {});
}

/**
 * Revoke invite
 * @param {string} organizationId - Organization ID
 * @param {string} inviteId - Invite ID
 * @returns {Promise<void>}
 */
export async function revokeInvite(organizationId, inviteId) {
  return del(`/v1/organizations/${organizationId}/invites/${inviteId}`);
}

/**
 * Update member role
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string} role - New role (admin, dev, operator)
 * @returns {Promise<Object>} Updated member
 */
export async function updateMemberRole(organizationId, memberId, role) {
  return patch(`/v1/organizations/${organizationId}/members/${memberId}`, { role });
}

/**
 * Remove team member
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @returns {Promise<void>}
 */
export async function removeMember(organizationId, memberId) {
  return del(`/v1/organizations/${organizationId}/members/${memberId}`);
}

/**
 * Transfer organization ownership
 * @param {string} organizationId - Organization ID
 * @param {string} newOwnerId - New owner user ID
 * @returns {Promise<Object>} Updated organization
 */
export async function transferOwnership(organizationId, newOwnerId) {
  return post(`/v1/organizations/${organizationId}/transfer-ownership`, {
    new_owner_id: newOwnerId,
  });
}

/**
 * Get team snapshot (for dashboard)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Team snapshot with counts and recent activity
 */
export async function getTeamSnapshot(organizationId) {
  return get(`/v1/organizations/${organizationId}/team/snapshot`);
}

export default {
  listMembers,
  getMember,
  inviteMember,
  listInvites,
  resendInvite,
  revokeInvite,
  updateMemberRole,
  removeMember,
  transferOwnership,
  getTeamSnapshot,
};
