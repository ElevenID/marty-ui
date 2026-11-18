import { getJoinOrganizationErrorText } from './joinOrganizationFlow';

export const INVITE_ACCEPT_STATES = {
  LOADING: 'loading',
  VALID: 'valid',
  ACCEPTING: 'accepting',
  ACCEPTED: 'accepted',
  EXPIRED: 'expired',
  INVALID: 'invalid',
  ERROR: 'error',
  LOGIN_REQUIRED: 'login_required',
};

export function getInviteAcceptJoinUrl(token) {
  return `/organizations/join?inviteToken=${encodeURIComponent(token || '')}`;
}

export function getInviteAcceptLoginReturnUrl(token) {
  return getInviteAcceptJoinUrl(token);
}

export function resolveInviteAcceptEntry({ token, isAuthenticated }) {
  if (!token) {
    return {
      shouldValidate: false,
      redirectTo: null,
      state: INVITE_ACCEPT_STATES.INVALID,
      error: 'No invitation token provided',
    };
  }

  if (isAuthenticated) {
    return {
      shouldValidate: false,
      redirectTo: getInviteAcceptJoinUrl(token),
      state: INVITE_ACCEPT_STATES.LOADING,
      error: null,
    };
  }

  return {
    shouldValidate: true,
    redirectTo: null,
    state: INVITE_ACCEPT_STATES.LOADING,
    error: null,
  };
}

export function resolveInviteAcceptValidation({ invitation, isAuthenticated }) {
  if (!invitation?.valid) {
    if (invitation?.expired) {
      return {
        state: INVITE_ACCEPT_STATES.EXPIRED,
        invitation: null,
        error: invitation?.message || 'This invitation has expired',
      };
    }

    return {
      state: INVITE_ACCEPT_STATES.INVALID,
      invitation: null,
      error: invitation?.message || 'Invitation not found or has been cancelled',
    };
  }

  return {
    state: isAuthenticated ? INVITE_ACCEPT_STATES.VALID : INVITE_ACCEPT_STATES.LOGIN_REQUIRED,
    invitation,
    error: null,
  };
}

export function resolveInviteAcceptSuccess({ invitation, acceptedInvitation }) {
  return {
    state: INVITE_ACCEPT_STATES.ACCEPTED,
    invitation: {
      ...(invitation || {}),
      ...(acceptedInvitation || {}),
    },
    error: null,
    redirectTo: '/my-applications',
  };
}

export function getInviteAcceptErrorText(error, getErrorMessage, fallbackMessage) {
  return getJoinOrganizationErrorText(error, getErrorMessage, fallbackMessage);
}