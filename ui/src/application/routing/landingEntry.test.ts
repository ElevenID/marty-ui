import { describe, expect, it } from 'vitest';

import {
  clearLandingAuthError,
  getLandingAuthError,
  getLandingEntryDecision,
} from './landingEntry';

describe('landingEntry helpers', () => {
  it('extracts a decoded auth error from search params', () => {
    const params = new URLSearchParams('auth_error=Login+failed%3A+access_denied');
    expect(getLandingAuthError(params)).toBe('Login failed: access_denied');
    expect(getLandingAuthError(new URLSearchParams(''))).toBeNull();
  });

  it('returns a new search params object without auth_error', () => {
    const params = new URLSearchParams('auth_error=Denied&foo=bar');
    const result = clearLandingAuthError(params);

    expect(result.get('auth_error')).toBeNull();
    expect(result.get('foo')).toBe('bar');
    expect(params.get('auth_error')).toBe('Denied');
  });

  it('navigates authenticated users and renders for unauthenticated users', () => {
    expect(getLandingEntryDecision({ isAuthenticated: true, isLoading: false })).toEqual({
      action: 'navigate',
      redirectTo: '/console/applicant',
    });

    expect(getLandingEntryDecision({ isAuthenticated: false, isLoading: false })).toEqual({
      action: 'render',
      redirectTo: null,
    });
  });

  it('stays in loading state while auth is unresolved', () => {
    expect(getLandingEntryDecision({ isAuthenticated: false, isLoading: true })).toEqual({
      action: 'loading',
      redirectTo: null,
    });
  });
});