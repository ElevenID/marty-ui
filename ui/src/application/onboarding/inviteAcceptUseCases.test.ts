import { describe, expect, it, vi } from 'vitest';

import { INVITE_ACCEPT_STATES } from './inviteAcceptFlow';
import {
  loadInviteAcceptInvitation,
  submitInviteAcceptInvitation,
} from './inviteAcceptUseCases';

describe('inviteAccept use cases', () => {
  it('returns redirect or token errors before validation when appropriate', async () => {
    await expect(loadInviteAcceptInvitation({
      token: null,
      isAuthenticated: false,
      validateOrganizationInvitation: vi.fn(),
    })).resolves.toEqual({
      state: INVITE_ACCEPT_STATES.INVALID,
      invitation: null,
      error: 'No invitation token provided',
      redirectTo: null,
    });

    await expect(loadInviteAcceptInvitation({
      token: 'token-1',
      isAuthenticated: true,
      validateOrganizationInvitation: vi.fn(),
    })).resolves.toEqual({
      state: INVITE_ACCEPT_STATES.LOADING,
      invitation: null,
      error: null,
      redirectTo: '/organizations/join?inviteToken=token-1',
    });
  });

  it('validates invitations and returns login-required or expired states', async () => {
    await expect(loadInviteAcceptInvitation({
      token: 'token-1',
      isAuthenticated: false,
      validateOrganizationInvitation: vi.fn().mockResolvedValue({ valid: true, organization_name: 'Acme' }),
    })).resolves.toEqual({
      state: INVITE_ACCEPT_STATES.LOGIN_REQUIRED,
      invitation: { valid: true, organization_name: 'Acme' },
      error: null,
      redirectTo: null,
    });

    await expect(loadInviteAcceptInvitation({
      token: 'token-2',
      isAuthenticated: false,
      validateOrganizationInvitation: vi.fn().mockResolvedValue({ valid: false, expired: true, message: 'Expired' }),
    })).resolves.toEqual({
      state: INVITE_ACCEPT_STATES.EXPIRED,
      invitation: null,
      error: 'Expired',
      redirectTo: null,
    });
  });

  it('accepts invitations and falls back to readable errors', async () => {
    await expect(submitInviteAcceptInvitation({
      token: 'token-1',
      invitation: { organization_name: 'Acme' },
      acceptOrganizationInvitation: vi.fn().mockResolvedValue({ organization_id: 'org-1' }),
    })).resolves.toEqual({
      state: INVITE_ACCEPT_STATES.ACCEPTED,
      invitation: {
        organization_name: 'Acme',
        organization_id: 'org-1',
      },
      error: null,
      redirectTo: '/my-applications',
    });

    await expect(submitInviteAcceptInvitation({
      token: 'token-2',
      invitation: { organization_name: 'Acme' },
      acceptOrganizationInvitation: vi.fn().mockRejectedValue({ response: { error: { user_message: 'Already accepted' } } }),
      getErrorMessageFn: vi.fn().mockReturnValue('Already accepted'),
    })).resolves.toEqual({
      state: INVITE_ACCEPT_STATES.ERROR,
      invitation: { organization_name: 'Acme' },
      error: 'Already accepted',
      redirectTo: null,
    });
  });
});