import { describe, expect, it } from 'vitest';
import { navigateToAuthApi, navigateToPasskeyProvider, resolveAuthBaseUrl } from '../authApiOrigin';
import { safeNavigationDestination } from '../../application/routing/safeNavigation';

const enrollment = (origin = 'https://api.elevenid.test') => `${origin}/realms/11id/protocol/openid-connect/auth?`
  + new URLSearchParams({ kc_action: 'webauthn-register-passwordless',
    redirect_uri: 'https://api.elevenid.test/v1/auth/callback', state: 'synthetic-one-time-state' });

describe('Auth API origin', () => {
  it('opens API-hosted enrollment without broadening the real general navigation guard', () => {
    const assigned: string[] = [];
    const location = { href: 'https://console.elevenid.test/console/profile', assign: (url: string) => assigned.push(url) };
    const target = enrollment();
    expect(safeNavigationDestination(target, location)).toBeNull();
    navigateToPasskeyProvider(target, 'https://api.elevenid.test', undefined, location);
    expect(assigned).toEqual([target]);
    expect(safeNavigationDestination(target, location)).toBeNull();
  });

  it('requires explicit configuration for a separately hosted enrollment provider', () => {
    const assigned: string[] = [];
    const location = { href: 'https://console.elevenid.test/console', assign: (url: string) => assigned.push(url) };
    const target = enrollment('https://identity.elevenid.test');
    expect(() => navigateToPasskeyProvider(target, 'https://api.elevenid.test', '', location)).toThrow();
    navigateToPasskeyProvider(target, 'https://api.elevenid.test', 'https://identity.elevenid.test', location);
    expect(assigned).toEqual([target]);
    expect(() => navigateToPasskeyProvider(target, 'https://api.elevenid.test', 'https://identity.elevenid.test/realms/11id', location)).toThrow();
  });

  it.each([
    enrollment('https://untrusted.test'),
    enrollment().replace('https://api.', 'http://api.'),
    enrollment().replace('https://api.', 'https://user:password@api.'),
    `${enrollment()}#fragment`, ` ${enrollment()}`,
    `${enrollment()}&kc_action=webauthn-register-passwordless`,
    enrollment().replace('webauthn-register-passwordless', 'delete-account'),
    enrollment().replace('redirect_uri=', 'wrong_redirect='),
    `${enrollment()}&redirect_uri=https%3A%2F%2Funtrusted.test%2Fcallback`,
    enrollment().replace('api.elevenid.test%2Fv1%2Fauth%2Fcallback', 'untrusted.test%2Fcallback'),
    '/realms/11id/protocol/openid-connect/auth', 'javascript:alert(1)',
    `blob:${enrollment()}`,
  ])('refuses an unsafe or unrelated enrollment destination %s', (target) => {
    const assigned: string[] = [];
    expect(() => navigateToPasskeyProvider(target, 'https://api.elevenid.test', '', {
      href: 'https://console.elevenid.test/console', assign: (url: string) => assigned.push(url),
    })).toThrow(expect.objectContaining({ code: 'AUTH_CONFIGURATION' }));
    expect(assigned).toEqual([]);
  });
  it('navigates only to login or registration on the configured API', () => {
    const assigned: string[] = [];
    const location = { href: 'https://console.elevenid.test/console', assign: (url: string) => assigned.push(url) };
    navigateToAuthApi('https://api.elevenid.test/v1/auth/login?redirect_uri=%2Fconsole', 'https://api.elevenid.test', location);
    expect(assigned).toEqual(['https://api.elevenid.test/v1/auth/login?redirect_uri=%2Fconsole']);
    for (const destination of ['https://untrusted.test/v1/auth/login', 'https://api.elevenid.test/v1/auth/me',
      'https://user:password@api.elevenid.test/v1/auth/login']) {
      expect(() => navigateToAuthApi(destination, 'https://api.elevenid.test', location))
        .toThrow(expect.objectContaining({ code: 'AUTH_CONFIGURATION' }));
    }
    expect(assigned).toHaveLength(1);
  });
  it('keeps the same-origin self-hosted transport when no API origin is set', () => {
    expect(resolveAuthBaseUrl(undefined)).toBe('/v1/auth');
    expect(resolveAuthBaseUrl('')).toBe('/v1/auth');
  });

  it('normalizes an explicitly configured HTTPS origin', () => {
    expect(resolveAuthBaseUrl('https://api.elevenid.test/')).toBe('https://api.elevenid.test/v1/auth');
    expect(resolveAuthBaseUrl('https://api.elevenid.test:8443')).toBe('https://api.elevenid.test:8443/v1/auth');
  });

  it.each(['http://localhost:8000', 'http://127.0.0.1:8000', 'http://[::1]:8000'])(
    'allows loopback development at %s', (origin) => {
      expect(resolveAuthBaseUrl(origin)).toBe(`${origin}/v1/auth`);
    },
  );

  it.each([
    'http://api.elevenid.test', '//api.elevenid.test', '/api',
    'https://user:password@api.elevenid.test', 'https://api.elevenid.test/api',
    'https://api.elevenid.test?token=value', 'https://api.elevenid.test#fragment',
    ' https://api.elevenid.test', 'javascript:alert(1)',
  ])('refuses an invalid credential destination %s', (origin) => {
    expect(() => resolveAuthBaseUrl(origin)).toThrow(expect.objectContaining({ code: 'AUTH_CONFIGURATION' }));
  });
});
