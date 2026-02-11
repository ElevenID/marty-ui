/**
 * Permissions System
 * 
 * Defines role-based access control (RBAC) for the application.
 * 
 * Roles:
 * - admin: Organization administrator (full access)
 * - dev: Developer (create/edit resources, no team management)
 * - operator: Operator (view-only, can manage flows and issuance)
 * 
 * Resources:
 * - trust: Trust profiles, trusted issuers, revocation
 * - template: Credential templates, application templates
 * - policy: Presentation policies, compliance profiles
 * - deployment: Deployment profiles, API keys, webhooks
 * - flow: Flow definitions and instances
 * - issuance: Credential issuance
 * - team: Team members, invites, roles
 * - audit: Audit logs
 * - org: Organization settings
 * - signing-key: Signing keys management
 * 
 * Actions:
 * - view: View resource details and lists
 * - create: Create new resources
 * - edit: Edit existing resources
 * - delete: Delete resources
 * - execute: Execute actions (e.g., issue credentials, rotate keys)
 */

// Wildcard permission
const ALL = '*';

/**
 * Permission matrix defining what each role can do
 */
export const PERMISSIONS = {
  admin: {
    view: [ALL],
    create: [ALL],
    edit: [ALL],
    delete: [ALL],
    execute: [ALL],
  },
  dev: {
    view: [ALL],
    create: [
      'trust',
      'template',
      'policy',
      'deployment',
      'flow',
    ],
    edit: [
      'trust',
      'template',
      'policy',
      'deployment',
      'flow',
    ],
    delete: [
      'template',
      'policy',
      'flow',
    ],
    execute: [
      'flow',
    ],
  },
  operator: {
    view: [
      'flow',
      'issuance',
      'audit',
      'deployment',
      'template',
      'policy',
    ],
    create: [
      'issuance',
      'flow', // can start flow instances
    ],
    edit: [],
    delete: [],
    execute: [
      'flow',
      'issuance',
    ],
  },
};

/**
 * Check if a role has permission for a resource and action
 * 
 * @param {string} role - User role (admin, dev, operator)
 * @param {string} resource - Resource type
 * @param {string} action - Action type (view, create, edit, delete, execute)
 * @returns {boolean} - Whether the role has permission
 */
export function hasPermission(role, resource, action) {
  if (!role || !resource || !action) {
    return false;
  }

  const rolePermissions = PERMISSIONS[role];
  if (!rolePermissions) {
    return false;
  }

  const allowedResources = rolePermissions[action];
  if (!allowedResources) {
    return false;
  }

  // Check for wildcard permission
  if (allowedResources.includes(ALL)) {
    return true;
  }

  // Check for specific resource permission
  return allowedResources.includes(resource);
}

/**
 * Get user-friendly message for permission denial
 * 
 * @param {string} role - User role
 * @param {string} action - Action attempted
 * @returns {string} - User-friendly message
 */
export function getPermissionDeniedMessage(role, action) {
  const actionLabels = {
    view: 'view',
    create: 'create',
    edit: 'edit',
    delete: 'delete',
    execute: 'perform',
  };

  const roleLabels = {
    admin: 'Administrator',
    dev: 'Developer',
    operator: 'Operator',
  };

  return `You don't have permission to ${actionLabels[action] || action} this resource. Your role is ${roleLabels[role] || role}. Contact an administrator to request access.`;
}

/**
 * Get all permissions for a role
 * 
 * @param {string} role - User role
 * @returns {Object} - All permissions for the role
 */
export function getRolePermissions(role) {
  return PERMISSIONS[role] || {
    view: [],
    create: [],
    edit: [],
    delete: [],
    execute: [],
  };
}

/**
 * Check if role can perform any action on a resource
 * 
 * @param {string} role - User role
 * @param {string} resource - Resource type
 * @returns {boolean} - Whether the role can interact with the resource at all
 */
export function canAccessResource(role, resource) {
  return (
    hasPermission(role, resource, 'view') ||
    hasPermission(role, resource, 'create') ||
    hasPermission(role, resource, 'edit') ||
    hasPermission(role, resource, 'delete') ||
    hasPermission(role, resource, 'execute')
  );
}

/**
 * Resource display names for user-facing messages
 */
export const RESOURCE_LABELS = {
  trust: 'Trust Profiles',
  template: 'Templates',
  policy: 'Policies',
  deployment: 'Deployment Profiles',
  flow: 'Flows',
  issuance: 'Issuance',
  team: 'Team Management',
  audit: 'Audit Logs',
  org: 'Organization Settings',
  'signing-key': 'Signing Keys',
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
