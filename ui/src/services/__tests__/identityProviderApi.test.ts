import { afterEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { getIdentityProvider } from '../identityProviderApi';

const provider = {
  provider_mode: 'external', provider_name: 'Example Identity',
  registration_supported: false, passkey_enrollment_supported: false,
  provider_logout_supported: false,
  account_url: 'https://identity.example/account', recovery_url: null,
};

afterEach(() => vi.restoreAllMocks());

describe('identity provider capabilities', () => {
  it('returns only the public capability contract without deriving permissions', async () => {
    server.use(http.get('*/v1/auth/provider', () => HttpResponse.json({
      ...provider, roles: ['admin'], client_secret: 'must-not-propagate',
    })));
    const fetch = vi.spyOn(window, 'fetch');
    await expect(getIdentityProvider()).resolves.toEqual(provider);
    expect(fetch).toHaveBeenCalledWith('/v1/auth/provider', expect.objectContaining({
      credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    }));
  });

  it.each(['javascript:alert(1)', 'http://identity.example/account',
    'https://user:password@identity.example/account', '/account', ' https://identity.example/account'])
  ('rejects an unsafe account destination %s', async account_url => {
    server.use(http.get('*/v1/auth/provider', () => HttpResponse.json({ ...provider, account_url })));
    await expect(getIdentityProvider()).rejects.toThrow('Sign-in provider details are temporarily unavailable.');
  });

  it.each([null, {}, { ...provider, provider_name: '' }, { ...provider, registration_supported: 'true' },
    { ...provider, provider_mode: 'unrecognized' }, { ...provider, recovery_url: 'javascript:alert(1)' }])
  ('rejects an invalid capability response without displaying its body: %j', async payload => {
    server.use(http.get('*/v1/auth/provider', () => HttpResponse.json(payload)));
    await expect(getIdentityProvider()).rejects.toThrow('Sign-in provider details are temporarily unavailable.');
  });

  it('does not expose a proxy failure body', async () => {
    server.use(http.get('*/v1/auth/provider', () => new HttpResponse('private diagnostic data', { status: 503 })));
    await expect(getIdentityProvider()).rejects.toThrow('Sign-in provider details are temporarily unavailable.');
  });

  it('aborts stalled discovery and clears its deadline', async () => {
    vi.useFakeTimers();
    let requestSignal: AbortSignal | undefined;
    vi.spyOn(globalThis, 'fetch').mockImplementation((_url, options) => new Promise((_resolve, reject) => {
      requestSignal = options?.signal || undefined;
      requestSignal?.addEventListener('abort', () => reject(new DOMException('Request aborted', 'AbortError')));
    }));
    try {
      const result = expect(getIdentityProvider()).rejects.toThrow('Sign-in provider details are temporarily unavailable.');
      await vi.advanceTimersByTimeAsync(10_000);
      await result;
      expect(requestSignal?.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('cancels the underlying request when its consumer unmounts', async () => {
    const controller = new AbortController();
    vi.spyOn(globalThis, 'fetch').mockImplementation((_url, options) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener('abort', () => reject(new DOMException('Request aborted', 'AbortError')));
    }));
    const result = expect(getIdentityProvider({ signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    await result;
  });
});
