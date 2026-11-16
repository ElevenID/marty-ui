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


describe('validated login return destinations', () => {
  it('preserves path, query, and fragment from state and next', () => {
    expect(getLoginEntryRedirect({ from: { pathname: '/console/org', search: '?page=2', hash: '#member' } })).toBe('/console/org?page=2#member');
    expect(getLoginEntryRedirect(null, '/', '?next=' + encodeURIComponent('/console/org?page=2#member'))).toBe('/console/org?page=2#member');
  });
  it('rejects attacker-controlled state, next, and fallback destinations', () => {
    for (const destination of ['https://example.invalid/', '//example.invalid/pricing', 'javascript:/pricing/?alert(1):alert(1)', 'data:text/html,hello', '/\\evil.example/', ' /pricing', '/pricing\n']) {
      expect(getLoginEntryRedirect(null, '/console', '?next=' + encodeURIComponent(destination))).toBe('/console');
      expect(getLoginEntryRedirect({ from: { pathname: destination } }, '/console')).toBe('/console');
      expect(getLoginEntryRedirect(null, destination)).toBe('/');
    }
  });
  it('rejects every literal ASCII control before URL parsing can normalize it', () => {
    for (const code of [...Array.from({ length: 32 }, (_, index) => index), 127]) {
      const destination = `/console/${String.fromCharCode(code)}org`;
      expect(getLoginEntryRedirect({ from: { pathname: destination } }, '/console')).toBe('/console');
      expect(getLoginEntryRedirect(null, '/console', '?next=' + encodeURIComponent(destination))).toBe('/console');
    }
    expect(getLoginEntryRedirect({ from: { pathname: '/console/org', search: '?name=José' } })).toBe('/console/org?name=Jos%C3%A9');
  });
});
