import {
  JOIN_ORGANIZATION_INVITE_STATES,
  getJoinOrganizationErrorText,
  normalizeJoinOrganizationInvitation,
  resolveJoinByCodeSuccess,
  resolveJoinInvitationAcceptSuccess,
  resolveJoinOrganizationPreviewSelection,
  resolveJoinSelectedOrganizationSuccess,
} from './joinOrganizationFlow';

export async function validateJoinOrganizationInvitation({ inviteToken, validateOrganizationInvitation, getErrorMessage }) {
  try {
    const data = await validateOrganizationInvitation(inviteToken);
    if (!data?.valid) {
      const inviteMessage =
        (typeof data?.message === 'string' && data.message) ||
        data?.error?.user_message ||
        data?.error?.message ||
        'Invitation is invalid or expired';
      throw new Error(inviteMessage);
    }

    const normalizedInvitation = normalizeJoinOrganizationInvitation(data);

    return {
      inviteState: JOIN_ORGANIZATION_INVITE_STATES.VALID,
      invitation: data,
      selectedOrg: normalizedInvitation.selectedOrg,
      error: null,
    };
  } catch (error) {
    return {
      inviteState: JOIN_ORGANIZATION_INVITE_STATES.ERROR,
      invitation: null,
      selectedOrg: null,
      error: getJoinOrganizationErrorText(error, getErrorMessage, 'Failed to validate invitation'),
    };
  }
}

export async function loadJoinOrganizationDiscoverableOrganizations({ orgIdFromQuery, discoverOrganizations, getErrorMessage }) {
  try {
    const organizations = await discoverOrganizations({ limit: 100 });
    return {
      organizations: organizations || [],
      selectedOrg: resolveJoinOrganizationPreviewSelection(organizations || [], orgIdFromQuery),
      error: null,
    };
  } catch (error) {
    return {
      organizations: [],
      selectedOrg: null,
      error: getJoinOrganizationErrorText(error, getErrorMessage, 'Failed to load organizations'),
    };
  }
}

export async function loadJoinOrganizationSelection({ orgIdFromQuery, organizations, isAuthenticated, getOrganization, getErrorMessage }) {
  if (!orgIdFromQuery) {
    return {
      selectedOrg: null,
      error: null,
    };
  }

  const fromList = resolveJoinOrganizationPreviewSelection(organizations, orgIdFromQuery);
  if (fromList) {
    return {
      selectedOrg: fromList,
      error: null,
    };
  }

  if (!isAuthenticated) {
    return {
      selectedOrg: null,
      error: null,
    };
  }

  try {
    const organization = await getOrganization(orgIdFromQuery);
    return {
      selectedOrg: organization,
      error: null,
    };
  } catch (error) {
    return {
      selectedOrg: null,
      error: getJoinOrganizationErrorText(error, getErrorMessage, 'Failed to load organization details'),
    };
  }
}

export async function submitJoinOrganizationByCode({ joinCode, joinByCode, refreshMemberships, setActiveOrgId }) {
  const result = await joinByCode(joinCode.trim().toUpperCase());
  const resolved = resolveJoinByCodeSuccess(result);

  if (resolved.successState === 'joined') {
    await refreshMemberships();
    await setActiveOrgId(resolved.organization.id);
  }

  return resolved;
}

export async function submitJoinSelectedOrganization({ selectedOrg, joinOrganization, refreshMemberships, setActiveOrgId }) {
  if (selectedOrg?.join_mechanism !== 'open') {
    throw new Error('This organization is not open for direct join. Use a join code or invitation link.');
  }

  const result = await joinOrganization(selectedOrg.id);
  const resolved = resolveJoinSelectedOrganizationSuccess(selectedOrg, result);

  if (resolved.successState === 'joined') {
    await refreshMemberships();
    await setActiveOrgId(selectedOrg.id);
  }

  return resolved;
}

export async function acceptJoinOrganizationInvitation({ inviteToken, invitation, selectedOrg, acceptOrganizationInvitation, refreshMemberships, setActiveOrgId }) {
  const data = await acceptOrganizationInvitation(inviteToken);
  const resolved = resolveJoinInvitationAcceptSuccess({ data, invitation, selectedOrg });

  if (resolved.organizationId) {
    await refreshMemberships();
    await setActiveOrgId(resolved.organizationId);
  }

  return resolved;
}
