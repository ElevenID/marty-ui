/**
 * Pure auth/session helpers.
 *
 * These helpers intentionally avoid React and browser framework dependencies.
 */

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
  const hasOrganizations = organizations.length > 0;

  return {
    apply: true,
    'org:view': hasOrganizations || roles.includes('vendor') || roles.includes('administrator'),
    'org:manage': roles.includes('vendor') || roles.includes('administrator'),
    'org:issue': roles.includes('vendor') || roles.includes('administrator'),
    'admin:platform': roles.includes('administrator'),
    ...fromApi,
  };
}

/**
 * Fallback memberships when the organization endpoint is unavailable.
 *
 * @param {Object|null|undefined} rawUser
 * @param {{ organizations: Array<{id: string, name: string|null}> }} [parsedClaim]
 * @returns {Array<{id: string, name: string|null}>}
 */
export function getFallbackOrganizations(rawUser, parsedClaim = parseOrganizationClaim(rawUser?.organization)) {
  if (parsedClaim.organizations.length > 0) {
    return parsedClaim.organizations;
  }

  if (rawUser?.organization_id) {
    return [{
      id: rawUser.organization_id,
      name: rawUser.organization_name || null,
    }];
  }

  return [];
}

/**
 * Resolve the memberships to use in auth state.
 *
 * @param {Object|null|undefined} rawUser
 * @param {Array<{id: string, name: string|null}>|null|undefined} fetchedOrganizations
 * @returns {Array<{id: string, name: string|null}>}
 */
export function resolveUserOrganizations(rawUser, fetchedOrganizations) {
  if (Array.isArray(fetchedOrganizations) && fetchedOrganizations.length > 0) {
    return fetchedOrganizations;
  }

  return getFallbackOrganizations(rawUser);
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
      ? { id: rawUser.organization_id, name: rawUser.organization_name || null }
      : null)
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

  return {
    ...rawUser,
    organization_id: activeOrganization?.id || null,
    organization_name: activeOrganization?.name || null,
    organizations,
    capabilities: deriveCapabilities(rawUser, organizations),
  };
}

/**
 * Update auth user state when the active organization changes.
 *
 * @param {Object|null|undefined} previousUser
 * @param {string|null|undefined} orgId
 * @returns {Object|null|undefined}
 */
export function updateUserActiveOrganization(previousUser, orgId) {
  if (!previousUser) {
    return previousUser;
  }

  const memberships = previousUser.organizations || [];
  const selected = memberships.find((entry) => entry.id === orgId);
  const resolvedOrganization = selected || (orgId ? { id: orgId, name: null } : null);

  if (!resolvedOrganization && orgId) {
    return previousUser;
  }

  const nextMemberships = selected
    ? memberships
    : orgId
      ? [...memberships, resolvedOrganization]
      : memberships;

  const nextCapabilities = {
    ...(previousUser.capabilities || {}),
    ...(orgId ? { 'org:view': true } : {}),
  };

  return {
    ...previousUser,
    organization_id: resolvedOrganization?.id || null,
    organization_name: resolvedOrganization?.name || previousUser.organization_name,
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
    isAdministrator: hasCapability('admin:platform') || roles.includes('administrator'),
    isVendor: hasCapability('org:view') || hasCapability('org:manage') || roles.includes('vendor'),
    isApplicant: Boolean(user),
    capabilities,
  };
}
