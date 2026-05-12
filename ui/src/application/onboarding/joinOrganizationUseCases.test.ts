import { describe, expect, it, vi } from 'vitest';

import { JOIN_ORGANIZATION_INVITE_STATES } from './joinOrganizationFlow';
import {
  acceptJoinOrganizationInvitation,
  loadJoinOrganizationDiscoverableOrganizations,
  loadJoinOrganizationSelection,
  submitJoinOrganizationByCode,
  submitJoinSelectedOrganization,
  validateJoinOrganizationInvitation,
} from './joinOrganizationUseCases';

describe('joinOrganization use cases', () => {
  it('validates invitations and normalizes selected organization data', async () => {
    await expect(validateJoinOrganizationInvitation({
      inviteToken: 'token-1',
      validateOrganizationInvitation: vi.fn().mockResolvedValue({
        valid: true,
        organization_id: 'org-1',
        organization_name: 'Acme',
      }),
      getErrorMessage: vi.fn(),
    })).resolves.toEqual({
      inviteState: JOIN_ORGANIZATION_INVITE_STATES.VALID,
      invitation: {
        valid: true,
        organization_id: 'org-1',
        organization_name: 'Acme',
      },
      selectedOrg: {
        id: 'org-1',
        name: 'Acme',
        display_name: 'Acme',
        join_mechanism: 'invite',
        requires_approval: false,
        description: '',
      },
      error: null,
    });
  });

  it('loads discoverable organizations and falls back to readable errors', async () => {
    const organizations = [{ id: 'org-2', name: 'Beta' }];

    await expect(loadJoinOrganizationDiscoverableOrganizations({
      orgIdFromQuery: 'org-2',
      discoverOrganizations: vi.fn().mockResolvedValue(organizations),
      getErrorMessage: vi.fn(),
    })).resolves.toEqual({
      organizations,
      selectedOrg: organizations[0],
      error: null,
    });

    await expect(loadJoinOrganizationDiscoverableOrganizations({
      orgIdFromQuery: null,
      discoverOrganizations: vi.fn().mockRejectedValue({ response: { error: { user_message: 'Offline' } } }),
      getErrorMessage: vi.fn().mockReturnValue('[object Object]'),
    })).resolves.toEqual({
      organizations: [],
      selectedOrg: null,
      error: 'Offline',
    });
  });

  it('resolves selected organizations from the list or authenticated detail lookup', async () => {
    const organizations = [{ id: 'org-1', name: 'Acme' }];

    await expect(loadJoinOrganizationSelection({
      orgIdFromQuery: 'org-1',
      organizations,
      isAuthenticated: false,
      getOrganization: vi.fn(),
      getErrorMessage: vi.fn(),
    })).resolves.toEqual({
      selectedOrg: organizations[0],
      error: null,
    });

    await expect(loadJoinOrganizationSelection({
      orgIdFromQuery: 'org-9',
      organizations,
      isAuthenticated: true,
      getOrganization: vi.fn().mockResolvedValue({ id: 'org-9', name: 'Gamma' }),
      getErrorMessage: vi.fn(),
    })).resolves.toEqual({
      selectedOrg: { id: 'org-9', name: 'Gamma' },
      error: null,
    });

    await expect(loadJoinOrganizationSelection({
      orgIdFromQuery: 'org-stale',
      organizations,
      isAuthenticated: true,
      getOrganization: vi.fn().mockRejectedValue({ status: 403, message: 'Forbidden' }),
      getErrorMessage: vi.fn().mockReturnValue('Forbidden'),
    })).resolves.toEqual({
      selectedOrg: null,
      error: null,
    });

    await expect(loadJoinOrganizationSelection({
      orgIdFromQuery: 'org-stale',
      organizations,
      isAuthenticated: true,
      getOrganization: vi.fn().mockRejectedValue({ status: 500, message: 'Server exploded' }),
      getErrorMessage: vi.fn().mockReturnValue('Server exploded'),
    })).resolves.toEqual({
      selectedOrg: null,
      error: null,
    });

    await expect(loadJoinOrganizationSelection({
      orgIdFromQuery: 'org-stale',
      organizations: [],
      isAuthenticated: true,
      getOrganization: vi.fn().mockRejectedValue({ status: 500, message: 'Server exploded' }),
      getErrorMessage: vi.fn().mockReturnValue('Server exploded'),
    })).resolves.toEqual({
      selectedOrg: null,
      error: 'Server exploded',
    });
  });

  it('joins by code, direct join, and invitation accept while refreshing memberships', async () => {
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);

    await expect(submitJoinOrganizationByCode({
      joinCode: 'abcd1234',
      joinByCode: vi.fn().mockResolvedValue({
        organization: { id: 'org-1', name: 'Acme' },
        membership: { status: 'active' },
      }),
      refreshMemberships,
      setActiveOrgId,
    })).resolves.toEqual({
      organization: { id: 'org-1', name: 'Acme' },
      successOrgName: 'Acme',
      successState: 'joined',
    });

    expect(refreshMemberships).toHaveBeenCalledTimes(1);
    expect(setActiveOrgId).toHaveBeenCalledWith('org-1');

    await expect(submitJoinSelectedOrganization({
      selectedOrg: { id: 'org-2', name: 'Beta', join_mechanism: 'open' },
      joinOrganization: vi.fn().mockResolvedValue({ membership: { status: 'pending' } }),
      refreshMemberships: vi.fn(),
      setActiveOrgId: vi.fn(),
    })).resolves.toEqual({
      successOrgName: 'Beta',
      successState: 'pending',
    });

    await expect(acceptJoinOrganizationInvitation({
      inviteToken: 'token-1',
      invitation: { organization_id: 'org-3', organization_name: 'Gamma' },
      selectedOrg: null,
      acceptOrganizationInvitation: vi.fn().mockResolvedValue({ organization_id: 'org-3', organization_name: 'Gamma' }),
      refreshMemberships,
      setActiveOrgId,
    })).resolves.toEqual({
      organizationId: 'org-3',
      successOrgName: 'Gamma',
      inviteState: JOIN_ORGANIZATION_INVITE_STATES.ACCEPTED,
      successState: 'joined',
    });
  });

  it('rejects non-open direct joins', async () => {
    await expect(submitJoinSelectedOrganization({
      selectedOrg: { id: 'org-2', name: 'Beta', join_mechanism: 'invite' },
      joinOrganization: vi.fn(),
      refreshMemberships: vi.fn(),
      setActiveOrgId: vi.fn(),
    })).rejects.toThrow('This organization is not open for direct join. Use a join code or invitation link.');
  });
});
