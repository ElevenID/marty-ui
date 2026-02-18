/**
 * RBAC API Service
 * 
 * Manages roles, permissions, and role assignments.
 */

import { get, post, patch, del, put } from './api';

/**
 * Get the current user's permissions in an organization
 * @param {string} organizationId - Organization ID
 * @returns {Promise<{permissions: string[], roles: Array<{id: string, name: string, display_name: string}>}>}
 */
export async function getMyPermissions(organizationId) {
  return get(`/v1/organizations/${organizationId}/members/me/permissions`);
}

/**
 * List the permission catalog (grouped by resource)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Permission catalog grouped by resource
 */
export async function listPermissions(organizationId) {
  return get(`/v1/organizations/${organizationId}/permissions`);
}

/**
 * List roles in an organization
 * @param {string} organizationId - Organization ID
 * @param {boolean} [includeMemberCount=false] - Include member counts
 * @returns {Promise<Array>} List of roles
 */
export async function listRoles(organizationId, includeMemberCount = false) {
  const params = includeMemberCount ? '?include_member_count=true' : '';
  return get(`/v1/organizations/${organizationId}/roles${params}`);
}

/**
 * Create a custom role
 * @param {string} organizationId - Organization ID
 * @param {Object} data - Role data
 * @param {string} data.name - Unique role name
 * @param {string} data.display_name - Display name
 * @param {string} [data.description] - Description
 * @param {string[]} data.permission_ids - Permission IDs to include
 * @param {boolean} [data.is_default_for_new_members] - Default role for new members
 * @returns {Promise<Object>} Created role
 */
export async function createRole(organizationId, data) {
  return post(`/v1/organizations/${organizationId}/roles`, data);
}

/**
 * Get a role by ID
 * @param {string} organizationId - Organization ID
 * @param {string} roleId - Role ID
 * @returns {Promise<Object>} Role details
 */
export async function getRole(organizationId, roleId) {
  return get(`/v1/organizations/${organizationId}/roles/${roleId}`);
}

/**
 * Update a custom role
 * @param {string} organizationId - Organization ID
 * @param {string} roleId - Role ID
 * @param {Object} data - Fields to update
 * @returns {Promise<Object>} Updated role
 */
export async function updateRole(organizationId, roleId, data) {
  return patch(`/v1/organizations/${organizationId}/roles/${roleId}`, data);
}

/**
 * Delete a custom role
 * @param {string} organizationId - Organization ID
 * @param {string} roleId - Role ID
 * @param {string} [replacementRoleId] - Role to reassign members to
 * @returns {Promise<void>}
 */
export async function deleteRole(organizationId, roleId, replacementRoleId) {
  const params = replacementRoleId ? `?replacement_role_id=${replacementRoleId}` : '';
  return del(`/v1/organizations/${organizationId}/roles/${roleId}${params}`);
}

/**
 * Set all roles for a member (replace)
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string[]} roleIds - Role IDs to assign
 * @returns {Promise<Object>} Updated member roles
 */
export async function setMemberRoles(organizationId, memberId, roleIds) {
  return put(`/v1/organizations/${organizationId}/members/${memberId}/roles`, {
    role_ids: roleIds,
  });
}

/**
 * Add a role to a member
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string} roleId - Role ID to add
 * @returns {Promise<Object>} Updated member roles
 */
export async function addMemberRole(organizationId, memberId, roleId) {
  return post(`/v1/organizations/${organizationId}/members/${memberId}/roles/${roleId}`);
}

/**
 * Remove a role from a member
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string} roleId - Role ID to remove
 * @returns {Promise<Object>} Updated member roles
 */
export async function removeMemberRole(organizationId, memberId, roleId) {
  return del(`/v1/organizations/${organizationId}/members/${memberId}/roles/${roleId}`);
}
