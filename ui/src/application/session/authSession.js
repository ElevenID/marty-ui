/**
 * Pure auth/session helpers.
 *
 * These helpers intentionally avoid React and browser framework dependencies.
 */

export const DEFAULT_LOGIN_REDIRECT = '/console';

/**
 * Resolve the destination for user-initiated login actions.
 *
 * Route guards and deep-link flows pass explicit strings and keep their target.
 * Plain marketing/header login clicks pass no string (or a click event), so they
 * should land in the authenticated console instead of returning to a marketing page.
 *
 * @param {string|unknown} redirectUri
 * @returns {string}
 */
export function resolveInteractiveLoginRedirect(redirectUri) {
  return typeof redirectUri === 'string' ? redirectUri : DEFAULT_LOGIN_REDIRECT;
}

/**
 * Parse organization claim from Keycloak token.
 * Keycloak Organizations feature returns: { "org-id": { "name": "Org Name", ... } }
 *
 * @param {Object|null|undefined} orgClaim
 * @returns {{ id: string|null, name: string|null, organizations: Array<{id: string, name: string|null}> }}
 */
export function parseOrganizationClaim(orgClaim) {
  if (!orgClaim || typeof orgClaim !== 'object') {
    return { id: null, name: null, organizations: [] };
  }

  const orgIds = Object.keys(orgClaim);
  if (orgIds.length === 0) {
    return { id: null, name: null, organizations: [] };
  }

  const organizations = orgIds.map((orgId) => ({
    id: orgId,
    name: orgClaim[orgId]?.name || null,
  }));

  return {
    id: organizations[0]?.id || null,
    name: organizations[0]?.name || null,
    organizations,
  };
}

function getOrganizationDisplayName(organization) {
  return organization?.display_name || organization?.displayName || organization?.name || null;
}

/**
 * Normalize capabilities into a capability map.
 *
 * @param {string[]|Object<string, boolean>|null|undefined} rawCapabilities
 * @returns {Record<string, boolean>}
 */
export function normalizeCapabilities(rawCapabilities) {
  if (!rawCapabilities) return {};

  if (Array.isArray(rawCapabilities)) {
    return rawCapabilities.reduce((acc, capability) => {
      if (typeof capability === 'string' && capability.trim()) {
        acc[capability] = true;
      }
      return acc;
    }, {});
  }

  if (typeof rawCapabilities === 'object') {
    return Object.entries(rawCapabilities).reduce((acc, [capability, enabled]) => {
      acc[capability] = Boolean(enabled);
      return acc;
    }, {});
  }

  return {};
}

/**
 * Derive effective capabilities from roles, memberships, and API-provided capabilities.
 *
 * @param {Object|null|undefined} rawUser
 * @param {Array<{id: string, name: string|null}>} organizations
 * @returns {Record<string, boolean>}
 */
export function deriveCapabilities(rawUser, organizations = []) {
  const roles = rawUser?.roles || [];
  const fromApi = normalizeCapabilities(rawUser?.capabilities);
  const isCanvasLearnerOnly = isCanvasLtiLearnerOnly(rawUser);
  const hasOrganizations = !isCanvasLearnerOnly && getConsoleEligibleOrganizations(organizations).length > 0;
  const hasAdminRole = roles.includes('admin') || roles.includes('administrator');
  const hasOrgRole = roles.some((role) => ['vendor', 'org_admin', 'organization-admin'].includes(role));
  const roleDerivedCapabilities = {
    'org:view': hasOrganizations || hasOrgRole || hasAdminRole,
    'org:manage': hasOrgRole || hasAdminRole,
    'org:issue': hasOrgRole || hasAdminRole,
    'admin:platform': hasAdminRole,
  };

  return {
    apply: fromApi.apply !== undefined ? Boolean(fromApi.apply) : true,
    ...fromApi,
    'org:view': !isCanvasLearnerOnly && (Boolean(fromApi['org:view']) || roleDerivedCapabilities['org:view']),
    'org:manage': !isCanvasLearnerOnly && (Boolean(fromApi['org:manage']) || roleDerivedCapabilities['org:manage']),
    'org:issue': !isCanvasLearnerOnly && (Boolean(fromApi['org:issue']) || roleDerivedCapabilities['org:issue']),
    'admin:platform': Boolean(fromApi['admin:platform']) || roleDerivedCapabilities['admin:platform'],
  };
}

/**
 * Fallback memberships when the organizations endpoint is empty or unavailable.
 *
 * @param {Object|null|undefined} rawUser
 * @param {{ organizations: Array<{id: string, name: string|null}> }} [parsedClaim]
 * @returns {Array<{id: string, name: string|null, display_name?: string|null}>}
 */
export function getFallbackOrganizations(rawUser, parsedClaim = parseOrganizationClaim(rawUser?.organization)) {
  if (Array.isArray(rawUser?.organizations) && rawUser.organizations.length > 0) {
    return rawUser.organizations.map((organization) => ({
      ...organization,
      id: organization.id || organization.organization_id,
      name: organization.name || organization.display_name || organization.displayName || null,
      display_name: organization.display_name || organization.displayName || organization.name || null,
    })).filter((organization) => organization.id);
  }

  if (parsedClaim.organizations.length > 0) {
    return parsedClaim.organizations.map((organization) => ({
      ...organization,
      display_name: organization.name || null,
    }));
  }

  if (rawUser?.organization_id) {
    return [{
      id: rawUser.organization_id,
      name: rawUser.organization_name || null,
      display_name: rawUser.organization_name || null,
    }];
  }

  return [];
}

const APPLICANT_ONLY_PERMISSIONS = new Set([
  'organization:view',
  'credential-template:view',
  'application-template:view',
  'application:view',
  'issuance:view',
]);

const ORG_CONSOLE_ROLES = new Set([
  'owner',
  'admin',
  'administrator',
  'vendor',
  'org_admin',
  'organization-admin',
  'access_admin',
  'catalog_admin',
  'reviewer',
  'operator',
  'viewer',
]);

function rawUserHasOrgAuthority(rawUser) {
  const roles = rawUser?.roles || [];
  return roles.some((role) => ORG_CONSOLE_ROLES.has(role)) || ['administrator', 'vendor'].includes(rawUser?.user_type);
}

function isCanvasLtiLearnerOnly(rawUser) {
  const roles = rawUser?.roles || [];
  return roles.includes('canvas_lti_learner') && !rawUserHasOrgAuthority(rawUser);
}

function applicantOnlyMembership() {
  return {
    roles: [{ name: 'applicant' }],
    permissions: ['organization:view', 'credential-template:view', 'application-template:view', 'application:view', 'issuance:view'],
    has_org_console_access: false,
  };
}

function restrictOrganizationsToApplicantAccess(organizations = []) {
  return organizations.map((organization) => ({
    ...organization,
    membership: {
      ...(organization.membership || applicantOnlyMembership()),
      has_org_console_access: false,
    },
  }));
}

function isClaimedKeycloakOrganization(rawUser, orgId) {
  if (!orgId) {
    return false;
  }
  const parsed = parseOrganizationClaim(rawUser?.organization);
  return parsed.organizations.some((organization) => organization.id === orgId) || rawUser?.organization_id === orgId;
}

function promoteKeycloakOrganizationMembership(rawUser, organization) {
  if (!rawUserHasOrgAuthority(rawUser) || !isClaimedKeycloakOrganization(rawUser, organization?.id)) {
    return organization;
  }

  return {
    ...organization,
    membership: {
      ...(organization.membership || {}),
      has_org_console_access: true,
    },
  };
}

export function membershipHasOrgConsoleAccess(organization) {
  const membership = organization?.membership;

  if (!membership) {
    return true;
  }

  if (membership.has_org_console_access || membership.is_owner) {
    return true;
  }

  const roleNames = (membership.roles || []).map((role) => role?.name).filter(Boolean);
  if (roleNames.some((roleName) => ORG_CONSOLE_ROLES.has(roleName))) {
    return true;
  }

  const permissions = membership.permissions || [];
  return permissions.some((permission) => !APPLICANT_ONLY_PERMISSIONS.has(permission));
}

export function getConsoleEligibleOrganizations(organizations = []) {
  if (!Array.isArray(organizations)) {
    return [];
  }

  return organizations.filter((organization) => membershipHasOrgConsoleAccess(organization));
}

function mergeFetchedAndClaimOrganizations(rawUser, fetchedOrganizations = []) {
  const fallbackOrganizations = getFallbackOrganizations(rawUser);
  if (!Array.isArray(fetchedOrganizations) || fetchedOrganizations.length === 0) {
    return fallbackOrganizations;
  }

  const byId = new Map(fallbackOrganizations.map((organization) => [organization.id, organization]));
  for (const organization of fetchedOrganizations) {
    const claimOrganization = byId.get(organization.id);
    const merged = claimOrganization
      ? {
        ...claimOrganization,
        ...organization,
        name: organization.name || claimOrganization.name,
        display_name: organization.display_name || claimOrganization.display_name || claimOrganization.name,
      }
      : organization;
    byId.set(organization.id, promoteKeycloakOrganizationMembership(rawUser, merged));
  }

  return Array.from(byId.values());
}

/**
 * Resolve the memberships to use in auth state.
 *
 * @param {Object|null|undefined} rawUser
 * @param {Array<{id: string, name: string|null}>|null|undefined} fetchedOrganizations
 * @returns {Array<{id: string, name: string|null}>}
 */
export function resolveUserOrganizations(rawUser, fetchedOrganizations) {
  const organizations = mergeFetchedAndClaimOrganizations(rawUser, fetchedOrganizations);
  return isCanvasLtiLearnerOnly(rawUser)
    ? restrictOrganizationsToApplicantAccess(organizations)
    : organizations;
}

/**
 * Determine the active organization from storage, memberships, or user claims.
 *
 * @param {Object} params
 * @param {string|null|undefined} params.storedOrgId
 * @param {Array<{id: string, name: string|null}>} params.organizations
 * @param {Object|null|undefined} params.rawUser
 * @returns {{id: string, name: string|null} | null}
 */
export function resolveActiveOrganization({ storedOrgId, organizations = [], rawUser }) {
  return (
    organizations.find((entry) => entry.id === storedOrgId) ||
    organizations[0] ||
    (rawUser?.organization_id
      ? {
        id: rawUser.organization_id,
        name: rawUser.organization_name || null,
        display_name: rawUser.organization_name || null,
      }
      : null) ||
    null
  );
}

function resolveDefaultApplicantOrganization({ rawUser, organizations = [], activeOrganization }) {
  const explicitDefaultOrgId = rawUser?.default_organization_id || null;
  const explicitDefaultOrganization = explicitDefaultOrgId
    ? organizations.find((entry) => entry.id === explicitDefaultOrgId)
      || {
        id: explicitDefaultOrgId,
        name: rawUser?.default_organization_name || null,
        display_name: rawUser?.default_organization_name || null,
      }
    : null;

  const claimedOrganization = rawUser?.organization_id
    ? organizations.find((entry) => entry.id === rawUser.organization_id) || null
    : null;

  return (
    explicitDefaultOrganization ||
    claimedOrganization ||
    organizations[0] ||
    activeOrganization ||
    (rawUser?.organization_id
      ? {
        id: rawUser.organization_id,
        name: rawUser.organization_name || null,
        display_name: rawUser.organization_name || null,
      }
      : null) ||
    null
  );
}

/**
 * Build the enriched auth user shape used by the context.
 *
 * @param {Object|null|undefined} rawUser
 * @param {Array<{id: string, name: string|null}>|null|undefined} fetchedOrganizations
 * @param {string|null|undefined} storedOrgId
 * @returns {Object|null}
 */
export function createEnrichedUser(rawUser, fetchedOrganizations, storedOrgId) {
  if (!rawUser) {
    return null;
  }

  const organizations = resolveUserOrganizations(rawUser, fetchedOrganizations);
  const activeOrganization = resolveActiveOrganization({
    storedOrgId,
    organizations,
    rawUser,
  });
  const defaultApplicantOrganization = resolveDefaultApplicantOrganization({
    rawUser,
    organizations,
    activeOrganization,
  });

  return {
    ...rawUser,
    organization_id: activeOrganization?.id || null,
    organization_name: getOrganizationDisplayName(activeOrganization),
    default_organization_id: defaultApplicantOrganization?.id || null,
    default_organization_name: getOrganizationDisplayName(defaultApplicantOrganization),
    organizations,
    capabilities: deriveCapabilities(rawUser, organizations),
  };
}

/**
 * Update auth user state when the active organization changes.
 *
 * @param {Object|null|undefined} previousUser
 * @param {string|null|undefined} orgId
 * @param {Object|null|undefined} selectedOrganization
 * @returns {Object|null|undefined}
 */
export function updateUserActiveOrganization(previousUser, orgId, selectedOrganization = null) {
  if (!previousUser) {
    return previousUser;
  }

  const memberships = previousUser.organizations || [];
  const normalizedSelectedOrganization = selectedOrganization && orgId
    ? {
      ...selectedOrganization,
      id: selectedOrganization.id || selectedOrganization.organization_id,
      name: selectedOrganization.name || selectedOrganization.display_name || selectedOrganization.displayName || null,
      display_name: selectedOrganization.display_name || selectedOrganization.displayName || selectedOrganization.name || null,
    }
    : null;
  const existingMembership = memberships.find((entry) => entry.id === orgId);
  const selected = existingMembership
    || (normalizedSelectedOrganization?.id === orgId ? normalizedSelectedOrganization : null);
  const resolvedOrganization = selected || (orgId ? { id: orgId, name: null } : null);

  if (!resolvedOrganization && orgId) {
    return previousUser;
  }

  const nextMemberships = existingMembership
    ? memberships
    : orgId
      ? [...memberships, resolvedOrganization]
      : memberships;

  const nextCapabilities = { ...(previousUser.capabilities || {}) };
  if (orgId) {
    nextCapabilities['org:view'] = Boolean(selected && membershipHasOrgConsoleAccess(selected));
  }

  const nextOrganizationId = resolvedOrganization?.id || null;
  const nextOrganizationName = resolvedOrganization
    ? (getOrganizationDisplayName(resolvedOrganization) || previousUser.organization_name || null)
    : null;

  // Preserve referential stability when the requested org is already active so
  // auth/bootstrap effects do not keep retriggering on identical state writes.
  if (
    (previousUser.organization_id || null) === nextOrganizationId &&
    (previousUser.organization_name || null) === nextOrganizationName &&
    nextMemberships === memberships &&
    (!orgId || previousUser.capabilities?.['org:view'] === true)
  ) {
    return previousUser;
  }

  return {
    ...previousUser,
    organization_id: nextOrganizationId,
    organization_name: nextOrganizationName,
    organizations: nextMemberships,
    capabilities: nextCapabilities,
  };
}

/**
 * Derive auth flags for presentation/use in contexts.
 *
 * @param {Object|null|undefined} user
 * @returns {{isAdministrator: boolean, isVendor: boolean, isApplicant: boolean, capabilities: Record<string, boolean>}}
 */
export function getAuthFlags(user) {
  const roles = user?.roles || [];
  const capabilities = user?.capabilities || {};
  const hasCapability = (capability) => Boolean(capabilities[capability]);

  return {
    isAdministrator: hasCapability('admin:platform') || roles.includes('administrator') || roles.includes('admin'),
    isVendor: hasCapability('org:view') || hasCapability('org:manage') || roles.includes('vendor'),
    isApplicant: Boolean(user),
    capabilities,
  };
}
