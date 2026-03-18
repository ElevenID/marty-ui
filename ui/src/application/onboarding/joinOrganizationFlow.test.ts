import { describe, expect, it, vi } from 'vitest';

import {
  JOIN_ORGANIZATION_INVITE_STATES,
  filterDiscoverableOrganizations,
  getJoinOrganizationErrorText,
  getJoinOrganizationMethodLabel,
  getJoinOrganizationReturnTo,
  normalizeJoinOrganizationInvitation,
  resolveJoinByCodeSuccess,
  resolveJoinInvitationAcceptSuccess,
  resolveJoinOrganizationPreviewSelection,
  resolveJoinSelectedOrganizationSuccess,
  shouldRequireJoinOrganizationLogin,
} from './joinOrganizationFlow';

describe('joinOrganizationFlow helpers', () => {
  it('formats join labels, return paths, and login requirements', () => {
    expect(getJoinOrganizationMethodLabel('open')).toBe('Open');
    expect(getJoinOrganizationMethodLabel('')).toBe('Invite only');
    expect(getJoinOrganizationReturnTo({ pathname: '/organizations/join', search: '?orgId=org-1' })).toBe('/organizations/join?orgId=org-1');
    expect(shouldRequireJoinOrganizationLogin({ authLoading: false, isAuthenticated: false })).toBe(true);
    expect(shouldRequireJoinOrganizationLogin({ authLoading: true, isAuthenticated: false })).toBe(false);
  });

  it('filters organizations and resolves selected previews', () => {
    const organizations = [
      { id: 'org-1', name: 'Acme Health', description: 'Issuer' },
      { id: 'org-2', display_name: 'Beta Labs', description: 'Verifier' },
    ];

    expect(filterDiscoverableOrganizations(organizations, 'beta')).toEqual([organizations[1]]);
    expect(resolveJoinOrganizationPreviewSelection(organizations, 'org-1')).toEqual(organizations[0]);
    expect(resolveJoinOrganizationPreviewSelection(organizations, 'missing')).toBeNull();
  });

  it('normalizes invitation payloads and extracts resilient errors', () => {
    expect(normalizeJoinOrganizationInvitation({
      organization_id: 'org-1',
      organization_name: 'Acme',
      organization_description: 'Trusted issuer',
    })).toMatchObject({
      selectedOrg: {
        id: 'org-1',
        name: 'Acme',
        display_name: 'Acme',
        join_mechanism: 'invite',
        description: 'Trusted issuer',
      },
    });

    const error = { response: { errors: [{ user_message: 'Invite expired' }] } };
    expect(getJoinOrganizationErrorText(error, vi.fn().mockReturnValue('[object Object]'), 'Fallback')).toBe('Invite expired');
  });

  it('maps join success outcomes for code, open join, and invitations', () => {
    expect(resolveJoinByCodeSuccess({
      organization: { id: 'org-1', name: 'Acme' },
      membership: { status: 'pending' },
    })).toEqual({
      organization: { id: 'org-1', name: 'Acme' },
      successOrgName: 'Acme',
      successState: 'pending',
    });

    expect(resolveJoinSelectedOrganizationSuccess(
      { id: 'org-1', display_name: 'Acme' },
      { membership: { status: 'active' } },
    )).toEqual({
      successOrgName: 'Acme',
      successState: 'joined',
    });

    expect(resolveJoinInvitationAcceptSuccess({
      data: { organization_id: 'org-1', organization_name: 'Acme' },
    })).toEqual({
      organizationId: 'org-1',
      successOrgName: 'Acme',
      inviteState: JOIN_ORGANIZATION_INVITE_STATES.ACCEPTED,
      successState: 'joined',
    });
  });
});
