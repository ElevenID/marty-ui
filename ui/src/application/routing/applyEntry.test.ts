import { describe, expect, it } from 'vitest';

import {
  APPLY_CONTEXT_MAX_AGE_MS,
  APPLY_JOIN_ORG_STORAGE_KEY,
  buildApplyEntryContext,
  getApplyEntryDecision,
  getApplyLoginRedirectUrl,
  isApplyContextFresh,
} from './applyEntry';

describe('applyEntry helpers', () => {
  it('builds deep-link apply context safely', () => {
    expect(buildApplyEntryContext({
      credentialType: 'mdl',
      orgId: 'org-1',
      pathname: '/apply/mdl',
      search: '?org_id=org-1',
      now: 123,
    })).toEqual({
      credentialType: 'mdl',
      orgId: 'org-1',
      timestamp: 123,
      returnUrl: '/apply/mdl?org_id=org-1',
    });
  });

  it('checks whether apply context is still fresh', () => {
    expect(isApplyContextFresh({ timestamp: 1_000 }, 1_000 + APPLY_CONTEXT_MAX_AGE_MS - 1)).toBe(true);
    expect(isApplyContextFresh({ timestamp: 1_000 }, 1_000 + APPLY_CONTEXT_MAX_AGE_MS)).toBe(false);
    expect(isApplyContextFresh(null, 1_000)).toBe(false);
  });

  it('builds login redirect urls', () => {
    expect(getApplyLoginRedirectUrl('/apply/mdl?org_id=org-1')).toBe('/login?return_to=%2Fapply%2Fmdl%3Forg_id%3Dorg-1');
  });

  it('redirects unauthenticated users through browser navigation', () => {
    expect(getApplyEntryDecision({
      isAuthenticated: false,
      credentialType: 'mdl',
      orgId: 'org-1',
      pathname: '/apply/mdl',
      search: '?org_id=org-1',
      now: 42,
    })).toEqual({
      kind: 'redirect-browser',
      context: {
        credentialType: 'mdl',
        orgId: 'org-1',
        timestamp: 42,
        returnUrl: '/apply/mdl?org_id=org-1',
      },
      loginUrl: '/login?return_to=%2Fapply%2Fmdl%3Forg_id%3Dorg-1',
      storage: {},
    });
  });

  it('routes authenticated users into org join, specific apply, or catalog paths', () => {
    expect(getApplyEntryDecision({
      isAuthenticated: true,
      user: { organization_id: 'org-2' },
      credentialType: 'mdl',
      orgId: 'org-1',
      pathname: '/apply/mdl',
      search: '?org_id=org-1',
    })).toEqual({
      kind: 'navigate',
      context: expect.objectContaining({
        credentialType: 'mdl',
        orgId: 'org-1',
        returnUrl: '/apply/mdl?org_id=org-1',
      }),
      destination: '/console/applicant?org_required=org-1',
      navigationState: null,
      storage: {
        [APPLY_JOIN_ORG_STORAGE_KEY]: 'org-1',
      },
    });

    expect(getApplyEntryDecision({
      isAuthenticated: true,
      user: { organization_id: 'org-1' },
      credentialType: 'mdl',
      orgId: 'org-1',
      pathname: '/apply/mdl',
      search: '?org_id=org-1',
      locationState: { credential: { id: 'cfg-1' } },
    })).toEqual({
      kind: 'navigate',
      context: expect.objectContaining({
        credentialType: 'mdl',
        orgId: 'org-1',
      }),
      destination: '/console/applicant/apply/mdl',
      navigationState: { credential: { id: 'cfg-1' } },
      storage: {},
    });

    expect(getApplyEntryDecision({
      isAuthenticated: true,
      user: { organization_id: 'org-1' },
      credentialType: null,
      orgId: null,
      pathname: '/apply',
      search: '',
    })).toEqual({
      kind: 'navigate',
      context: expect.objectContaining({
        credentialType: null,
        orgId: null,
        returnUrl: '/apply',
      }),
      destination: '/console/applicant/catalog',
      navigationState: null,
      storage: {},
    });
  });
});
