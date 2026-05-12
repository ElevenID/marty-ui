/**
 * Team Management API Service
 * 
 * Manages team members, invites, and role assignments.
 */

import { get, post, del } from './api';
import { buildTruthyQueryString, withQuery } from './queryUtils';

/**
 * List team members
 * @param {string} organizationId - Organization ID
 * @param {Object} filters - Query filters
 * @param {string} filters.role - Filter by role
 * @param {string} filters.status - Filter by status
 * @returns {Promise<Array>} List of team members
 */
export async function listMembers(organizationId, filters = {}) {
  const queryString = buildTruthyQueryString({
    role: filters.role,
    status: filters.status,
  });
  const path = `/v1/organizations/${organizationId}/members`;
  return get(withQuery(path, queryString));
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
 * @param {string[]} invite.role_ids - Role IDs to assign
 * @param {string} invite.message - Optional personal message
 * @returns {Promise<Object>} Created invite
 */
export async function inviteMember(organizationId, invite) {
  return post(`/v1/organizations/${organizationId}/members`, invite);
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
  removeMember,
  transferOwnership,
  getTeamSnapshot,
};
