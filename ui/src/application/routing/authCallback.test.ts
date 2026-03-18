import { describe, expect, it, vi } from 'vitest';

import {
  completeAuthCallback,
  decodeAuthCallbackState,
  exchangeAuthCallbackCode,
  getAuthCallbackCodeState,
  getAuthCallbackErrorFromParams,
  resolveAuthCallbackRedirect,
  waitForAuthCallbackConsole,
} from './authCallback';

describe('authCallback helpers', () => {
  it('reads callback errors and code/state from search params', () => {
    const params = new URLSearchParams('error=access_denied&error_description=Denied&code=abc&state=xyz');

    expect(getAuthCallbackErrorFromParams(params)).toBe('Denied');
    expect(getAuthCallbackCodeState(params)).toEqual({ code: 'abc', state: 'xyz' });
  });

  it('decodes state safely and resolves redirect destinations', () => {
    const state = btoa(JSON.stringify({ returnTo: '/console/org' }));

    expect(decodeAuthCallbackState(state)).toEqual({ returnTo: '/console/org' });
    expect(decodeAuthCallbackState('not-base64')).toEqual({});

    expect(resolveAuthCallbackRedirect({
      state,
      consoleContext: { mode: 'org' },
      getDefaultLandingPath: vi.fn(),
    })).toBe('/console/org');

    const getDefaultLandingPath = vi.fn().mockReturnValue('/console/applicant/catalog');
    expect(resolveAuthCallbackRedirect({
      state: btoa(JSON.stringify({ returnTo: '/' })),
      consoleContext: { mode: 'applicant' },
      getDefaultLandingPath,
      fallback: '/fallback',
    })).toBe('/console/applicant/catalog');
    expect(getDefaultLandingPath).toHaveBeenCalledWith({ mode: 'applicant' }, '/fallback');
  });

  it('waits for console loading to settle', async () => {
    const consoleContext = { isLoading: true };
    const sleep = vi.fn().mockImplementation(async () => {
      consoleContext.isLoading = false;
    });

    await expect(waitForAuthCallbackConsole({ consoleContext, sleep, maxAttempts: 5, delayMs: 1 })).resolves.toBe(1);
  });

  it('exchanges the callback code and requires an authorization code', async () => {
    const exchangeAuthCallback = vi.fn().mockResolvedValue({ ok: true });

    await expect(exchangeAuthCallbackCode({ code: 'abc', state: 'xyz', exchangeAuthCallback })).resolves.toEqual({ ok: true });
    expect(exchangeAuthCallback).toHaveBeenCalledWith({ code: 'abc', state: 'xyz' });

    await expect(exchangeAuthCallbackCode({ code: null, state: 'xyz', exchangeAuthCallback })).rejects.toThrow('No authorization code received');
  });

  it('completes callback flow and returns either redirect or error', async () => {
    const exchangeAuthCallback = vi.fn().mockResolvedValue({ ok: true });
    const refreshUser = vi.fn().mockResolvedValue(undefined);
    const getDefaultLandingPath = vi.fn().mockReturnValue('/console/applicant/catalog');
    const consoleContext = { isLoading: false };

    await expect(completeAuthCallback({
      searchParams: new URLSearchParams(`code=abc&state=${encodeURIComponent(btoa(JSON.stringify({ returnTo: '/' })))}`),
      refreshUser,
      consoleContext,
      getDefaultLandingPath,
      exchangeAuthCallback,
      sleep: vi.fn(),
    })).resolves.toEqual({
      redirectTo: '/console/applicant/catalog',
      error: null,
    });

    await expect(completeAuthCallback({
      searchParams: new URLSearchParams('error=access_denied'),
      refreshUser,
      consoleContext,
      getDefaultLandingPath,
      exchangeAuthCallback,
      sleep: vi.fn(),
    })).resolves.toEqual({
      redirectTo: null,
      error: 'access_denied',
    });

    await expect(completeAuthCallback({
      searchParams: new URLSearchParams('code=abc'),
      refreshUser,
      consoleContext,
      getDefaultLandingPath,
      exchangeAuthCallback: vi.fn().mockRejectedValue(new Error('Authentication failed')),
      sleep: vi.fn(),
    })).resolves.toEqual({
      redirectTo: null,
      error: 'Authentication failed',
    });
  });
});
