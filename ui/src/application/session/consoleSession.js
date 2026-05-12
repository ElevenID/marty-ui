/**
 * Pure console/session helpers.
 *
 * These helpers hold console mode and organization selection rules without router dependencies.
 */

const APPLICANT_MODE = 'applicant';
const ORG_MODE = 'org';

/**
 * Normalize preferences payloads from the backend.
 *
 * @param {Object|null|undefined} preferences
 * @returns {{last_view_mode: 'applicant' | 'org', last_active_org_id: string | null}}
 */
export function normalizeConsolePreferences(preferences) {
  return {
    last_view_mode: preferences?.last_view_mode === ORG_MODE ? ORG_MODE : APPLICANT_MODE,
    last_active_org_id: preferences?.last_active_org_id || null,
  };
}

/**
 * Resolve bootstrap console state from prefs and memberships.
 *
 * @param {Object} params
 * @param {Object|null|undefined} params.preferences
 * @param {Array<{id: string, name?: string|null}>|null|undefined} params.memberships
 * @param {string|null|undefined} params.localStoredOrgId
 * @returns {{mode: 'applicant' | 'org', activeOrgId: string | null}}
 */
export function resolveConsoleBootstrap({ preferences, memberships, localStoredOrgId }) {
  const normalizedPreferences = normalizeConsolePreferences(preferences);
  const safeMemberships = memberships || [];
  const hasMemberships = safeMemberships.length > 0;
  const restoredOrgId = normalizedPreferences.last_active_org_id || localStoredOrgId || null;

  // Prefer stored org ID if it exists in memberships
  let activeOrgId = safeMemberships.find((entry) => entry.id === restoredOrgId)
    ? restoredOrgId
    : null;

  const effectiveMode = hasMemberships ? normalizedPreferences.last_view_mode : APPLICANT_MODE;

  // Auto-select first membership when in org mode but no stored org matches.
  // Prevents falling through to the JWT organization_id which may be a system/sentinel org.
  if (effectiveMode === ORG_MODE && !activeOrgId && hasMemberships) {
    activeOrgId = safeMemberships[0].id;
  }

  return {
    mode: effectiveMode,
    activeOrgId,
  };
}

/**
 * Resolve the organization ID applicant-mode pages should use.
 *
 * @param {Object} params
 * @param {string|null|undefined} params.defaultOrganizationId
 * @param {string|null|undefined} params.currentOrganizationId
 * @param {Array<{id: string, name?: string|null}>|null|undefined} params.organizations
 * @returns {string | null}
 */
export function resolveApplicantOrganizationId({
  defaultOrganizationId,
  currentOrganizationId,
  organizations,
}) {
  const safeOrganizations = organizations || [];

  if (defaultOrganizationId) {
    return defaultOrganizationId;
  }

  if (currentOrganizationId && safeOrganizations.find((entry) => entry.id === currentOrganizationId)) {
    return currentOrganizationId;
  }

  if (safeOrganizations.length > 0) {
    return safeOrganizations[0].id;
  }

  return currentOrganizationId || null;
}

/**
 * Decide where switching console mode should send the user.
 *
 * @param {Object} params
 * @param {'applicant' | 'org'} params.newMode
 * @param {string|null|undefined} params.activeOrgId
 * @param {Array<{id: string, name?: string|null}>|null|undefined} params.memberships
 * @returns {{mode: 'applicant' | 'org', activeOrgId: string | null, destination: string, authOrgId?: string, persistence: {last_view_mode: 'applicant' | 'org', last_active_org_id: string | null}}}
 */
export function resolveModeChange({ newMode, activeOrgId, memberships }) {
  const safeMemberships = memberships || [];

  if (newMode === APPLICANT_MODE) {
    return {
      mode: APPLICANT_MODE,
      activeOrgId: null,
      destination: '/console/applicant/catalog',
      persistence: {
        last_view_mode: APPLICANT_MODE,
        last_active_org_id: null,
      },
    };
  }

  if (safeMemberships.length === 1) {
    const singleOrg = safeMemberships[0];
    return {
      mode: ORG_MODE,
      activeOrgId: singleOrg.id,
      destination: '/console/org',
      authOrgId: singleOrg.id,
      persistence: {
        last_view_mode: ORG_MODE,
        last_active_org_id: singleOrg.id,
      },
    };
  }

  if (activeOrgId) {
    return {
      mode: ORG_MODE,
      activeOrgId,
      destination: '/console/org',
      persistence: {
        last_view_mode: ORG_MODE,
        last_active_org_id: activeOrgId,
      },
    };
  }

  return {
    mode: ORG_MODE,
    activeOrgId: null,
    destination: '/console/org/setup',
    persistence: {
      last_view_mode: ORG_MODE,
      last_active_org_id: null,
    },
  };
}

/**
 * Validate and resolve active organization selection.
 *
 * @param {Object} params
 * @param {string|null|undefined} params.orgId
 * @param {'applicant' | 'org'} params.currentMode
 * @param {Array<{id: string, name?: string|null}>|null|undefined} params.memberships
 * @returns {{valid: boolean, mode: 'applicant' | 'org', activeOrgId: string | null, destination: string | null, persistence: {last_view_mode: 'applicant' | 'org', last_active_org_id: string | null} | null}}
 */
export function resolveActiveOrgSelection({ orgId, currentMode, memberships }) {
  const safeMemberships = memberships || [];

  if (orgId && !safeMemberships.find((entry) => entry.id === orgId)) {
    return {
      valid: false,
      mode: currentMode,
      activeOrgId: orgId || null,
      destination: null,
      persistence: null,
    };
  }

  const nextMode = orgId ? ORG_MODE : currentMode;
  const destination = orgId ? '/console/org' : null;

  return {
    valid: true,
    mode: nextMode,
    activeOrgId: orgId || null,
    destination,
    persistence: {
      last_view_mode: nextMode,
      last_active_org_id: orgId || null,
    },
  };
}

/**
 * Whether org console should be blocked until org selection.
 *
 * @param {'applicant' | 'org'} mode
 * @param {string|null|undefined} activeOrgId
 * @returns {boolean}
 */
export function isOrgConsoleBlocked(mode, activeOrgId) {
  return mode === ORG_MODE && activeOrgId === null;
}

/**
 * Get post-login landing path from console context.
 *
 * @param {Object} context
 * @param {'applicant' | 'org'} context.mode
 * @param {string|null|undefined} context.activeOrgId
 * @param {Array<{id: string, name?: string|null}>|null|undefined} context.memberships
 * @param {string} [fallback='/console/applicant/catalog']
 * @returns {string}
 */
export function getDefaultLandingPath(context, fallback = '/console/applicant/catalog') {
  const { mode, activeOrgId, memberships } = context;
  const safeMemberships = memberships || [];

  if (safeMemberships.length === 0) {
    return '/console/applicant/catalog';
  }

  if (mode === ORG_MODE && activeOrgId && safeMemberships.find((entry) => entry.id === activeOrgId)) {
    return '/console/org';
  }

  if (mode === APPLICANT_MODE || !activeOrgId) {
    return '/console/applicant/catalog';
  }

  return fallback;
}
