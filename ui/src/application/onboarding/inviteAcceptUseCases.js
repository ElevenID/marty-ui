import { getErrorMessage } from '../../services/api';
import {
  getInviteAcceptErrorText,
  resolveInviteAcceptEntry,
  resolveInviteAcceptSuccess,
  resolveInviteAcceptValidation,
} from './inviteAcceptFlow';

export async function loadInviteAcceptInvitation({
  token,
  isAuthenticated,
  validateOrganizationInvitation,
  getErrorMessageFn = getErrorMessage,
}) {
  const entry = resolveInviteAcceptEntry({ token, isAuthenticated });

  if (!entry.shouldValidate) {
    return {
      state: entry.state,
      invitation: null,
      error: entry.error,
      redirectTo: entry.redirectTo,
    };
  }

  try {
    const invitation = await validateOrganizationInvitation(token);
    const result = resolveInviteAcceptValidation({ invitation, isAuthenticated });
    return {
      state: result.state,
      invitation: result.invitation,
      error: result.error,
      redirectTo: null,
    };
  } catch (error) {
    return {
      state: 'error',
      invitation: null,
      error: getInviteAcceptErrorText(error, getErrorMessageFn, 'Failed to validate invitation'),
      redirectTo: null,
    };
  }
}

export async function submitInviteAcceptInvitation({
  token,
  invitation,
  acceptOrganizationInvitation,
  getErrorMessageFn = getErrorMessage,
}) {
  try {
    const acceptedInvitation = await acceptOrganizationInvitation(token);
    const result = resolveInviteAcceptSuccess({ invitation, acceptedInvitation });
    return {
      state: result.state,
      invitation: result.invitation,
      error: result.error,
      redirectTo: result.redirectTo,
    };
  } catch (error) {
    return {
      state: 'error',
      invitation,
      error: getInviteAcceptErrorText(error, getErrorMessageFn, 'Failed to accept invitation'),
      redirectTo: null,
    };
  }
}