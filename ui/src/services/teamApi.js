/**
 * Team Management API Service
 * 
 * Manages team members, invites, and role assignments.
 */

import { get, post, del } from './api';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const PAGE_SIZE = 500;

/**
 * List team members
 * @param {string} organizationId - Organization ID
 * @param {Object} filters - Query filters
 * @param {string} filters.role - Filter by role
 * @param {string} filters.status - Filter by status
 * @returns {Promise<Array>} List of team members
 */
export async function listMembers(organizationId, filters = {}, { isCurrent = () => true } = {}) {
  const orgId = requireOrganizationId(organizationId, 'loading team members');
  const path = `/v1/organizations/${encodeURIComponent(orgId)}/members`;
  const members = [];
  const seen = new Set();
  const ensureCurrent = () => {
    if (!isCurrent()) {
      const error = new Error('Team membership scope changed.');
      error.name = 'AbortError';
      throw error;
    }
  };
  let offset = 0;
  while (true) {
    ensureCurrent();
    const queryString = buildDefinedQueryString({
      role: filters.role || undefined, status: filters.status || undefined, limit: PAGE_SIZE, offset,
    });
    const page = await get(withQuery(path, queryString));
    ensureCurrent();
    if (!Array.isArray(page) || page.length > PAGE_SIZE || page.some(member => !member
      || typeof member.id !== 'string' || !member.id.trim() || member.organization_id !== orgId)) {
      throw new Error('Team members returned an invalid response.');
    }
    for (const member of page) {
      if (seen.has(member.id)) {
        throw new Error('The team membership inventory changed while loading. Refresh and try again.');
      }
      seen.add(member.id);
      members.push(member);
    }
    if (page.length < PAGE_SIZE) return members;
    offset += page.length;
  }
}

/**
 * Get team member by ID
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @returns {Promise<Object>} Team member details
 */
export async function getMember(organizationId, memberId) {
  const orgId = requireOrganizationId(organizationId, 'loading team member');
  return get(`/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`);
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
  const orgId = requireOrganizationId(organizationId, 'inviting team members');
  return post(`/v1/organizations/${encodeURIComponent(orgId)}/members`, invite);
}

/**
 * Remove team member
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @returns {Promise<void>}
 */
export async function removeMember(organizationId, memberId) {
  const orgId = requireOrganizationId(organizationId, 'removing team members');
  return del(`/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`);
}

/**
 * Transfer organization ownership
 * @param {string} organizationId - Organization ID
 * @param {string} newOwnerId - New owner user ID
 * @returns {Promise<Object>} Updated organization
 */
export async function transferOwnership(organizationId, newOwnerId) {
  const orgId = requireOrganizationId(organizationId, 'transferring organization ownership');
  return post(`/v1/organizations/${encodeURIComponent(orgId)}/transfer-ownership`, {
    new_owner_id: newOwnerId,
  });
}

/**
 * Get team snapshot (for dashboard)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Team snapshot with counts and recent activity
 */
export async function getTeamSnapshot(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading team snapshot');
  return get(`/v1/organizations/${encodeURIComponent(orgId)}/team/snapshot`);
}

export default {
  listMembers,
  getMember,
  inviteMember,
  removeMember,
  transferOwnership,
  getTeamSnapshot,
};
