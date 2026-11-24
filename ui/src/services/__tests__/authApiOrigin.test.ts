import { describe, expect, it } from 'vitest';
import { navigateToAuthApi, resolveAuthBaseUrl } from '../authApiOrigin';

describe('Auth API origin', () => {
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
