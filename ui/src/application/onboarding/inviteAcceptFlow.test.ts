import { describe, expect, it } from 'vitest';

import {
  getInviteAcceptJoinUrl,
  getInviteAcceptLoginReturnUrl,
  INVITE_ACCEPT_STATES,
  resolveInviteAcceptEntry,
  resolveInviteAcceptSuccess,
  resolveInviteAcceptValidation,
} from './inviteAcceptFlow';

describe('inviteAcceptFlow helpers', () => {
  it('builds join and login return URLs from the invitation token', () => {
    expect(getInviteAcceptJoinUrl('token-1')).toBe('/organizations/join?inviteToken=token-1');
    expect(getInviteAcceptLoginReturnUrl('token 1')).toBe('/organizations/join?inviteToken=token%201');
  });

  it('resolves missing tokens and authenticated redirects before validation', () => {
    expect(resolveInviteAcceptEntry({ token: null, isAuthenticated: false })).toEqual({
      shouldValidate: false,
      redirectTo: null,
      state: INVITE_ACCEPT_STATES.INVALID,
      error: 'No invitation token provided',
    });

    expect(resolveInviteAcceptEntry({ token: 'token-1', isAuthenticated: true })).toEqual({
      shouldValidate: false,
      redirectTo: '/organizations/join?inviteToken=token-1',
      state: INVITE_ACCEPT_STATES.LOADING,
      error: null,
    });
  });

  it('maps validation results into login-required, expired, or invalid states', () => {
    expect(resolveInviteAcceptValidation({
      invitation: { valid: true, organization_name: 'Acme' },
      isAuthenticated: false,
    })).toEqual({
      state: INVITE_ACCEPT_STATES.LOGIN_REQUIRED,
      invitation: { valid: true, organization_name: 'Acme' },
      error: null,
    });

    expect(resolveInviteAcceptValidation({
      invitation: { valid: false, expired: true, message: 'Expired link' },
      isAuthenticated: false,
    })).toEqual({
      state: INVITE_ACCEPT_STATES.EXPIRED,
      invitation: null,
      error: 'Expired link',
    });

    expect(resolveInviteAcceptValidation({
      invitation: { valid: false },
      isAuthenticated: false,
    })).toEqual({
      state: INVITE_ACCEPT_STATES.INVALID,
      invitation: null,
      error: 'Invitation not found or has been cancelled',
    });
  });

  it('merges accepted invitation details and redirects to applications', () => {
    expect(resolveInviteAcceptSuccess({
      invitation: { organization_name: 'Acme', email: 'user@example.com' },
      acceptedInvitation: { organization_id: 'org-1' },
    })).toEqual({
      state: INVITE_ACCEPT_STATES.ACCEPTED,
      invitation: {
        organization_name: 'Acme',
        email: 'user@example.com',
        organization_id: 'org-1',
      },
      error: null,
      redirectTo: '/my-applications',
    });
  });
});