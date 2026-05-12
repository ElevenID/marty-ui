import { describe, expect, it, vi } from 'vitest';
import { isConsolePath, redirectBrowser, shouldBrowserRedirect } from './appHandoff';

describe('appHandoff', () => {
  describe('isConsolePath', () => {
    it('matches console root and descendants', () => {
      expect(isConsolePath('/console')).toBe(true);
      expect(isConsolePath('/console/org/flows/definitions')).toBe(true);
      expect(isConsolePath('/')).toBe(false);
    });
  });

  describe('shouldBrowserRedirect', () => {
    it('requires browser redirect when entering console from non-console path', () => {
      expect(
        shouldBrowserRedirect({ currentPathname: '/', destination: '/console/org/flows/definitions' })
      ).toBe(true);
    });

    it('does not require browser redirect when already in console path', () => {
      expect(
        shouldBrowserRedirect({
          currentPathname: '/console/org',
          destination: '/console/org/flows/definitions',
        })
      ).toBe(false);
    });
  });

  describe('redirectBrowser', () => {
    it('does not redirect when destination resolves to current URL', () => {
      const location = {
        href: 'https://example.com/login',
        origin: 'https://example.com',
        pathname: '/login',
        search: '',
        hash: '',
        replace: vi.fn(),
        assign: vi.fn(),
      };

      const didRedirect = redirectBrowser('/login', { location });

      expect(didRedirect).toBe(false);
      expect(location.replace).not.toHaveBeenCalled();
      expect(location.assign).not.toHaveBeenCalled();
    });

    it('uses location.replace by default for real redirects', () => {
      const location = {
        href: 'https://example.com/console',
        origin: 'https://example.com',
        pathname: '/console',
        search: '',
        hash: '',
        replace: vi.fn(),
        assign: vi.fn(),
      };

      const didRedirect = redirectBrowser('/login', { location });

      expect(didRedirect).toBe(true);
      expect(location.replace).toHaveBeenCalledWith('/login');
      expect(location.assign).not.toHaveBeenCalled();
    });

    it('falls back to location.assign when replace is false', () => {
      const location = {
        href: 'https://example.com/console',
        origin: 'https://example.com',
        pathname: '/console',
        search: '',
        hash: '',
        replace: vi.fn(),
        assign: vi.fn(),
      };

      const didRedirect = redirectBrowser('/login', { location, replace: false });

      expect(didRedirect).toBe(true);
      expect(location.assign).toHaveBeenCalledWith('/login');
      expect(location.replace).not.toHaveBeenCalled();
    });
  });
});
