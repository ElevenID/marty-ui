/**
 * RBAC API Service
 * 
 * Manages roles, permissions, and role assignments.
 */

import { get, post, patch, del, put } from './api';
import { requireOrganizationId } from './queryUtils';

/**
 * Get the current user's permissions in an organization
 * @param {string} organizationId - Organization ID
 * @returns {Promise<{permissions: string[], roles: Array<{id: string, name: string, display_name: string}>}>}
 */
export async function getMyPermissions(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading permissions');
  return get(`/v1/organizations/${encodeURIComponent(orgId)}/members/me/permissions`);
}

/**
 * List the permission catalog (grouped by resource)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} Permission catalog grouped by resource
 */
export async function listPermissions(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading permission catalog');
  return get(`/v1/organizations/${encodeURIComponent(orgId)}/permissions`);
}

/**
 * List roles in an organization
 * @param {string} organizationId - Organization ID
 * @param {boolean} [includeMemberCount=false] - Include member counts
 * @returns {Promise<Array>} List of roles
 */
export async function listRoles(organizationId, includeMemberCount = false) {
  const orgId = requireOrganizationId(organizationId, 'loading roles');
  const params = includeMemberCount ? '?include_member_count=true' : '';
  return get(`/v1/organizations/${encodeURIComponent(orgId)}/roles${params}`);
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
  const orgId = requireOrganizationId(organizationId, 'creating roles');
  return post(`/v1/organizations/${encodeURIComponent(orgId)}/roles`, data);
}

/**
 * Get a role by ID
 * @param {string} organizationId - Organization ID
 * @param {string} roleId - Role ID
 * @returns {Promise<Object>} Role details
 */
export async function getRole(organizationId, roleId) {
  const orgId = requireOrganizationId(organizationId, 'loading roles');
  return get(`/v1/organizations/${encodeURIComponent(orgId)}/roles/${encodeURIComponent(roleId)}`);
}

/**
 * Update a custom role
 * @param {string} organizationId - Organization ID
 * @param {string} roleId - Role ID
 * @param {Object} data - Fields to update
 * @returns {Promise<Object>} Updated role
 */
export async function updateRole(organizationId, roleId, data) {
  const orgId = requireOrganizationId(organizationId, 'updating roles');
  return patch(`/v1/organizations/${encodeURIComponent(orgId)}/roles/${encodeURIComponent(roleId)}`, data);
}

/**
 * Delete a custom role
 * @param {string} organizationId - Organization ID
 * @param {string} roleId - Role ID
 * @param {string} [replacementRoleId] - Role to reassign members to
 * @returns {Promise<void>}
 */
export async function deleteRole(organizationId, roleId, replacementRoleId) {
  const orgId = requireOrganizationId(organizationId, 'deleting roles');
  const params = replacementRoleId ? `?replacement_role_id=${encodeURIComponent(replacementRoleId)}` : '';
  return del(`/v1/organizations/${encodeURIComponent(orgId)}/roles/${encodeURIComponent(roleId)}${params}`);
}

/**
 * Set all roles for a member (replace)
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string[]} roleIds - Role IDs to assign
 * @returns {Promise<Object>} Updated member roles
 */
export async function setMemberRoles(organizationId, memberId, roleIds) {
  const orgId = requireOrganizationId(organizationId, 'updating member roles');
  return put(`/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}/roles`, {
    role_ids: roleIds,
  });
}

/**
 * Add a single role to a member.
 * Prefer setMemberRoles for bulk updates to avoid race conditions.
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string} roleId - Role ID to add
 * @returns {Promise<Object>} Updated member roles
 */
export async function addMemberRole(organizationId, memberId, roleId) {
  const orgId = requireOrganizationId(organizationId, 'updating member roles');
  return post(`/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}/roles/${encodeURIComponent(roleId)}`);
}

/**
 * Remove a single role from a member.
 * Prefer setMemberRoles for bulk updates to avoid race conditions.
 * @param {string} organizationId - Organization ID
 * @param {string} memberId - Member ID
 * @param {string} roleId - Role ID to remove
 * @returns {Promise<Object>} Updated member roles
 */
export async function removeMemberRole(organizationId, memberId, roleId) {
  const orgId = requireOrganizationId(organizationId, 'updating member roles');
  return del(`/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}/roles/${encodeURIComponent(roleId)}`);
}
