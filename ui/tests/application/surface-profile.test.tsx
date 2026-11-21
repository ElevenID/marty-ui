import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import i18n from 'i18next';
import * as applicationConfig from '@ui-public-config';
import { getPublicLoginFallback, renderMarketingRoutes, renderPublicRoot } from '@ui-public-routes';
import { commerceExtensionEnabled, renderCommerceApplicationRoutes } from '@marty/commerce-extension';
import * as publicConfig from '../../src/variants/publicConfig.public';
import { redirectBrowser } from '../../src/application/routing/appHandoff';
import LoginPage from '../../src/components/LoginPage';
import { getApplyEntryDecision } from '../../src/application/routing/applyEntry';

const { auth } = vi.hoisted(() => ({
  auth: {
    isAuthenticated: true,
    isLoading: false,
    authError: null,
    login: vi.fn(),
    refreshUser: vi.fn(),
  },
}));

vi.mock('../../src/hooks/useAuth', () => ({ useAuth: () => auth }));

vi.mock('../../src/application/routing/appHandoff', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../src/application/routing/appHandoff')>(),
  redirectBrowser: vi.fn(() => true),
}));

afterEach(() => {
  vi.clearAllMocks();
  auth.isAuthenticated = true;
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
});

const namespaces = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor'];

describe('the selected application test profile', () => {
  it('resolves the application configuration while preserving public application capabilities and handoff links', () => {
    expect(applicationConfig.I18N_NAMESPACES).toEqual(namespaces);
    expect(applicationConfig.IS_SELFHOST_UI).toBe(false);
    expect(applicationConfig.SHOW_PUBLIC_LOGIN_BUTTON).toBe(publicConfig.SHOW_PUBLIC_LOGIN_BUTTON);
    expect(applicationConfig.DISABLE_PUBLIC_LOGIN_BUTTON).toBe(publicConfig.DISABLE_PUBLIC_LOGIN_BUTTON);
    expect(applicationConfig.ENABLE_ORGANIZATION_CREATION).toBe(publicConfig.ENABLE_ORGANIZATION_CREATION);
    expect(applicationConfig.PUBLIC_TABS).toBe(publicConfig.PUBLIC_TABS);
  });

  it('loads exactly the application English resources without a marketing namespace', () => {
    expect([...i18n.options.ns as string[]].sort()).toEqual([...namespaces].sort());
    expect(Object.keys(i18n.getDataByLanguage('en') || {}).sort()).toEqual([...namespaces].sort());
    for (const namespace of namespaces) expect(i18n.hasResourceBundle('en', namespace)).toBe(true);
    expect(i18n.hasResourceBundle('en', 'marketing')).toBe(false);
  });

  it('uses the real application root to open login through the shared browser handoff', () => {
    render(<MemoryRouter initialEntries={['/']}>{renderPublicRoot()}</MemoryRouter>);
    expect(screen.getByTestId('browser-redirect')).toBeVisible();
    expect(screen.getByText('Opening application...')).toBeVisible();
    expect(redirectBrowser).toHaveBeenCalledWith('/login', { replace: true });
    expect(getPublicLoginFallback()).toBe('/console');
  });

  it.each([false, true])('keeps the default sign-in destination in the application (authenticated=%s)', (isAuthenticated) => {
    auth.isAuthenticated = isAuthenticated;
    render(<MemoryRouter initialEntries={['/login']}>
      <LoginPage fallbackRedirectTo={getPublicLoginFallback()} />
    </MemoryRouter>);

    if (isAuthenticated) {
      expect(redirectBrowser).toHaveBeenCalledWith('/console');
      expect(auth.login).not.toHaveBeenCalled();
    } else {
      expect(auth.login).toHaveBeenCalledWith('/console');
      expect(redirectBrowser).not.toHaveBeenCalled();
      const loadingState = screen.getByTestId('login-page');
      expect(loadingState).toHaveStyle({
        display: 'flex',
        'flex-direction': 'column',
        'align-items': 'center',
        'justify-content': 'center',
        'min-height': `${window.innerHeight / 2}px`,
      });
    }
  });

  it.each([false, true])('respects a disabled console without returning to the website (authenticated=%s)', (isAuthenticated) => {
    auth.isAuthenticated = isAuthenticated;
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: ['public'] } };
    expect(getPublicLoginFallback()).toBe('/organizations');
    render(<MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<LoginPage fallbackRedirectTo={getPublicLoginFallback()} />} />
        <Route path="/organizations" element={<div>Application organizations</div>} />
      </Routes>
    </MemoryRouter>);

    expect(redirectBrowser).not.toHaveBeenCalled();
    if (isAuthenticated) {
      expect(screen.getByText('Application organizations')).toBeVisible();
      expect(auth.login).not.toHaveBeenCalled();
    } else {
      expect(auth.login).toHaveBeenCalledWith('/organizations');
    }
  });

  it.each([false, true])('preserves an explicit post-login path, query and fragment (authenticated=%s)', (isAuthenticated) => {
    auth.isAuthenticated = isAuthenticated;
    const destination = '/console/org/operate/applications/application-1?tab=documents#proof';
    render(<MemoryRouter initialEntries={[`/login?next=${encodeURIComponent(destination)}`]}>
      <LoginPage fallbackRedirectTo={getPublicLoginFallback()} />
    </MemoryRouter>);

    if (isAuthenticated) {
      expect(redirectBrowser).toHaveBeenCalledWith(destination);
      expect(auth.login).not.toHaveBeenCalled();
    } else {
      expect(auth.login).toHaveBeenCalledWith(destination);
      expect(redirectBrowser).not.toHaveBeenCalled();
    }
  });

  it.each([false, true])('returns an apply login handoff to its original credential, organization and fragment (authenticated=%s)', (isAuthenticated) => {
    auth.isAuthenticated = isAuthenticated;
    const destination = '/apply/credential-1?org_id=org-1#documents';
    const handoff = getApplyEntryDecision({
      isAuthenticated: false,
      credentialType: 'credential-1',
      orgId: 'org-1',
      pathname: '/apply/credential-1',
      search: '?org_id=org-1',
      hash: '#documents',
    });
    expect(handoff.context.returnUrl).toBe(destination);
    render(<MemoryRouter initialEntries={[handoff.loginUrl]}>
      <Routes>
        <Route path="/login" element={<LoginPage fallbackRedirectTo={getPublicLoginFallback()} />} />
        <Route path="/apply/credential-1" element={<div>Requested credential application</div>} />
      </Routes>
    </MemoryRouter>);

    expect(redirectBrowser).not.toHaveBeenCalled();
    if (isAuthenticated) {
      expect(screen.getByText('Requested credential application')).toBeVisible();
      expect(auth.login).not.toHaveBeenCalled();
    } else {
      expect(auth.login).toHaveBeenCalledWith(destination);
    }
  });

  it('keeps the public commerce implementation and exposes no website routes through the application adapter', () => {
    expect(commerceExtensionEnabled).toBe(false);
    expect(renderCommerceApplicationRoutes()).toBeNull();
    expect(renderMarketingRoutes({ login: vi.fn() })).toBeNull();
  });
});
