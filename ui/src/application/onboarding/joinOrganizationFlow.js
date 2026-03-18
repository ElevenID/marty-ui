export const JOIN_ORGANIZATION_INVITE_STATES = {
  LOADING: 'loading',
  VALID: 'valid',
  ACCEPTING: 'accepting',
  ACCEPTED: 'accepted',
  ERROR: 'error',
};

export function getJoinOrganizationMethodLabel(method) {
  const labels = {
    open: 'Open',
    code: 'Join code',
    invite: 'Invite only',
    domain: 'Domain',
  };

  return labels[method] || method || 'Invite only';
}

export function getJoinOrganizationReturnTo({ pathname = '', search = '' }) {
  return `${pathname}${search}`;
}

/**
 * @param {{ authLoading?: boolean, isAuthenticated?: boolean }} params
 */
export function shouldRequireJoinOrganizationLogin({ authLoading, isAuthenticated }) {
  return !authLoading && !isAuthenticated;
}

/**
 * @param {Array<{ id?: string, name?: string, display_name?: string, description?: string }>} organizations
 * @param {string} [searchQuery='']
 */
export function filterDiscoverableOrganizations(organizations = [], searchQuery = '') {
  const query = searchQuery.trim().toLowerCase();
  if (!query) {
    return organizations;
  }

  return organizations.filter((org) => {
    const name = (org.name || org.display_name || '').toLowerCase();
    const description = (org.description || '').toLowerCase();
    return name.includes(query) || description.includes(query);
  });
}

/**
 * @param {Array<{ id?: string }>} organizations
 * @param {string | null | undefined} orgIdFromQuery
 */
export function resolveJoinOrganizationPreviewSelection(organizations = [], orgIdFromQuery = null) {
  if (!orgIdFromQuery) {
    return null;
  }

  return organizations.find((org) => org.id === orgIdFromQuery) || null;
}

export function normalizeJoinOrganizationInvitation(invitation = {}) {
  return {
    ...invitation,
    selectedOrg: {
      id: invitation.organization_id,
      name: invitation.organization_name,
      display_name: invitation.organization_name,
      join_mechanism: 'invite',
      requires_approval: false,
      description: invitation.organization_description || '',
    },
  };
}

export function getJoinOrganizationErrorText(error, getErrorMessage, fallback) {
  const parsed = getErrorMessage(error);
  if (typeof parsed === 'string' && parsed.trim() && parsed !== '[object Object]') {
    return parsed;
  }

  const nestedUserMessage = error?.response?.error?.user_message || error?.response?.errors?.[0]?.user_message;
  if (typeof nestedUserMessage === 'string' && nestedUserMessage.trim()) {
    return nestedUserMessage;
  }

  const nestedMessage = error?.response?.error?.message;
  if (typeof nestedMessage === 'string' && nestedMessage.trim() && nestedMessage !== '[object Object]') {
    return nestedMessage;
  }

  return fallback;
}

/**
 * @param {{ organization?: { id?: string, name?: string, display_name?: string }, membership?: { status?: string } }} [result={}]
 */
export function resolveJoinByCodeSuccess(result = {}) {
  const organization = result?.organization;
  const membershipStatus = result?.membership?.status;

  if (!organization) {
    throw new Error('Join succeeded but organization details were missing');
  }

  return {
    organization,
    successOrgName: organization.name || organization.display_name || 'Organization',
    successState: membershipStatus === 'pending' ? 'pending' : 'joined',
  };
}

/**
 * @param {{ id?: string, name?: string, display_name?: string } | null | undefined} selectedOrg
 * @param {{ membership?: { status?: string } }} [result={}]
 */
export function resolveJoinSelectedOrganizationSuccess(selectedOrg, result = {}) {
  const membershipStatus = result?.membership?.status;
  return {
    successOrgName: selectedOrg?.name || selectedOrg?.display_name || 'Organization',
    successState: membershipStatus === 'pending' ? 'pending' : 'joined',
  };
}

/**
 * @param {{
 *   data?: { organization_id?: string, organization_name?: string },
 *   invitation?: { organization_id?: string, organization_name?: string } | null,
 *   selectedOrg?: { id?: string, name?: string } | null,
 * }} [params={}]
 */
export function resolveJoinInvitationAcceptSuccess({ data = {}, invitation = null, selectedOrg = null }) {
  const organizationId = data.organization_id || invitation?.organization_id || selectedOrg?.id || null;
  const successOrgName = data.organization_name || invitation?.organization_name || selectedOrg?.name || 'Organization';

  return {
    organizationId,
    successOrgName,
    inviteState: JOIN_ORGANIZATION_INVITE_STATES.ACCEPTED,
    successState: 'joined',
  };
}
