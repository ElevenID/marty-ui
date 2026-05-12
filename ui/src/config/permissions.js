/**
 * Permissions System
 * 
 * Organization-scoped Role-Based Access Control (RBAC).
 * 
 * Permissions are loaded from the backend via GET /v1/organizations/{id}/members/me/permissions
 * and stored as a flat set of "resource:action" keys (e.g. "credential-template:create").
 * 
 * This module provides helpers for checking permissions against the loaded set.
 * 
 * System Roles:
 * - owner: Full access + transfer ownership
 * - admin: Full access to all resources and settings
 * - member: Can create and manage resources; no team/org/role management
 * - viewer: Read-only access
 * 
 * Organizations can also create custom roles with arbitrary permission subsets.
 */

/**
 * Check if a permission set includes a specific resource:action
 * 
 * @param {Set<string>|string[]} permissions - The user's permission set
 * @param {string} resource - Resource type (e.g. "credential-template")
 * @param {string} action - Action type (e.g. "create")
 * @returns {boolean} Whether the permission is granted
 */
export function hasPermission(permissions, resource, action) {
  if (!permissions || !resource || !action) {
    return false;
  }
  const key = `${resource}:${action}`;
  if (permissions instanceof Set) {
    return permissions.has(key);
  }
  if (Array.isArray(permissions)) {
    return permissions.includes(key);
  }
  return false;
}

/**
 * Check if permissions include ANY of the given resource:action pairs
 * 
 * @param {Set<string>|string[]} permissions - The user's permission set
 * @param {Array<{resource: string, action: string}>} checks - Permissions to check
 * @returns {boolean}
 */
export function hasAnyPermission(permissions, checks) {
  if (!permissions || !checks || checks.length === 0) return false;
  return checks.some(({ resource, action }) => hasPermission(permissions, resource, action));
}

/**
 * Check if permissions include ALL of the given resource:action pairs
 * 
 * @param {Set<string>|string[]} permissions - The user's permission set
 * @param {Array<{resource: string, action: string}>} checks - Permissions to check
 * @returns {boolean}
 */
export function hasAllPermissions(permissions, checks) {
  if (!permissions || !checks || checks.length === 0) return false;
  return checks.every(({ resource, action }) => hasPermission(permissions, resource, action));
}

/**
 * Check if the user can access a resource in any way (any action)
 * 
 * @param {Set<string>|string[]} permissions - The user's permission set
 * @param {string} resource - Resource type
 * @returns {boolean}
 */
export function canAccessResource(permissions, resource) {
  if (!permissions || !resource) return false;
  const prefix = `${resource}:`;
  if (permissions instanceof Set) {
    for (const p of permissions) {
      if (p.startsWith(prefix)) return true;
    }
    return false;
  }
  if (Array.isArray(permissions)) {
    return permissions.some(p => p.startsWith(prefix));
  }
  return false;
}

/**
 * Get user-friendly message for permission denial
 * 
 * @param {string} action - Action attempted
 * @returns {string} - User-friendly message
 */
export function getPermissionDeniedMessage(action) {
  const actionLabels = {
    view: 'view',
    create: 'create',
    edit: 'edit',
    delete: 'delete',
    execute: 'perform',
  };

  return `You don't have permission to ${actionLabels[action] || action} this resource. Contact an administrator to request access.`;
}

/**
 * Resource display names for user-facing messages
 */
export const RESOURCE_LABELS = {
  'trust-profile': 'Trust Profiles',
  'trusted-issuer': 'Trusted Issuers',
  'credential-template': 'Credential Templates',
  'compliance-profile': 'Compliance Profiles',
  'presentation-policy': 'Presentation Policies',
  'revocation-profile': 'Revocation Profiles',
  'deployment-profile': 'Deployment Profiles',
  'flow-definition': 'Flow Definitions',
  'flow-instance': 'Flow Instances',
  issuance: 'Issuance',
  'application-template': 'Application Templates',
  application: 'Applications',
  organization: 'Organization Settings',
  team: 'Team Management',
  role: 'Role Management',
  'api-key': 'API Keys',
  'signing-key': 'Signing Keys',
  webhook: 'Webhooks',
  'integration-connector': 'Integration Connectors',
  notification: 'Notifications',
  audit: 'Audit Logs',
  verification: 'Verification',
};

/**
 * Get resource label for display
 * 
 * @param {string} resource - Resource type
 * @returns {string} - Display label
 */
export function getResourceLabel(resource) {
  return RESOURCE_LABELS[resource] || resource;
}
