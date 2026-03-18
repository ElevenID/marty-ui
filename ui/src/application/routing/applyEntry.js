/**
 * Pure helpers for the /apply deep-link entry flow.
 */

export const APPLY_CONTEXT_STORAGE_KEY = 'applyContext';
export const APPLY_JOIN_ORG_STORAGE_KEY = 'joinOrgId';
export const APPLY_CONTEXT_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * @param {{
 *   credentialType?: string | null,
 *   orgId?: string | null,
 *   pathname?: string,
 *   search?: string,
 *   now?: number,
 * }} params
 */
export function buildApplyEntryContext({ credentialType = null, orgId = null, pathname = '', search = '', now = Date.now() }) {
  return {
    credentialType: credentialType || null,
    orgId: orgId || null,
    timestamp: now,
    returnUrl: `${pathname}${search}`,
  };
}

export function isApplyContextFresh(context, now = Date.now(), maxAge = APPLY_CONTEXT_MAX_AGE_MS) {
  if (!context?.timestamp) {
    return false;
  }

  return now - context.timestamp < maxAge;
}

export function getApplyLoginRedirectUrl(returnUrl) {
  return `/login?return_to=${encodeURIComponent(returnUrl)}`;
}

/**
 * @param {{
 *   isAuthenticated: boolean,
 *   user?: { organization_id?: string | null } | null,
 *   credentialType?: string | null,
 *   orgId?: string | null,
 *   pathname?: string,
 *   search?: string,
 *   locationState?: any,
 *   now?: number,
 * }} params
 */
export function getApplyEntryDecision({
  isAuthenticated,
  user = null,
  credentialType = null,
  orgId = null,
  pathname = '',
  search = '',
  locationState = null,
  now = Date.now(),
}) {
  const context = buildApplyEntryContext({
    credentialType,
    orgId,
    pathname,
    search,
    now,
  });

  if (!isAuthenticated) {
    return {
      kind: 'redirect-browser',
      context,
      loginUrl: getApplyLoginRedirectUrl(context.returnUrl),
      storage: {},
    };
  }

  if (orgId && user?.organization_id !== orgId) {
    return {
      kind: 'navigate',
      context,
      destination: `/console/applicant?org_required=${orgId}`,
      navigationState: null,
      storage: {
        [APPLY_JOIN_ORG_STORAGE_KEY]: orgId,
      },
    };
  }

  if (credentialType) {
    return {
      kind: 'navigate',
      context,
      destination: `/console/applicant/apply/${credentialType}`,
      navigationState: locationState || null,
      storage: {},
    };
  }

  return {
    kind: 'navigate',
    context,
    destination: '/console/applicant/catalog',
    navigationState: null,
    storage: {},
  };
}
