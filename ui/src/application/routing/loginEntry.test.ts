import { describe, expect, it } from 'vitest';

import { getLoginEntryDecision, getLoginEntryRedirect } from './loginEntry';

describe('loginEntry helpers', () => {
  it('resolves the post-login redirect from location state', () => {
    expect(getLoginEntryRedirect({ from: { pathname: '/console/org' } })).toBe('/console/org');
    expect(getLoginEntryRedirect({ from: { pathname: '/console/applicant/apply/cfg-1', search: '?canvas_lti_state=state-1' } })).toBe('/console/applicant/apply/cfg-1?canvas_lti_state=state-1');
    expect(getLoginEntryRedirect(null)).toBe('/');
  });

  it('resolves the post-login redirect from a next query param', () => {
    expect(getLoginEntryRedirect(null, '/', '?next=%2Fconsole%2Fapplicant%2Fcatalog%3Fcanvas_lti_state%3Dstate-1')).toBe('/console/applicant/catalog?canvas_lti_state=state-1');
  });

  it('returns an idle action while auth state is still loading', () => {
    expect(getLoginEntryDecision({
      isAuthenticated: false,
      isLoading: true,
      redirectTo: '/console/org',
    })).toEqual({
      action: 'idle',
      redirectTo: null,
    });
  });

  it('navigates authenticated users to the intended destination', () => {
    expect(getLoginEntryDecision({
      isAuthenticated: true,
      isLoading: false,
      redirectTo: '/console/org',
    })).toEqual({
      action: 'navigate',
      redirectTo: '/console/org',
    });
  });

  it('starts login for unauthenticated users once loading completes', () => {
    expect(getLoginEntryDecision({
      isAuthenticated: false,
      isLoading: false,
      redirectTo: '/console/org',
    })).toEqual({
      action: 'login',
      redirectTo: null,
    });
  });
});
