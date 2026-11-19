import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import i18n from 'i18next';
import * as applicationConfig from '@ui-public-config';
import { getPublicLoginFallback, renderMarketingRoutes, renderPublicRoot } from '@ui-public-routes';
import { commerceExtensionEnabled, renderCommerceApplicationRoutes } from '@marty/commerce-extension';
import * as publicConfig from '../../src/variants/publicConfig.public';
import { redirectBrowser } from '../../src/application/routing/appHandoff';

vi.mock('../../src/application/routing/appHandoff', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../src/application/routing/appHandoff')>(),
  redirectBrowser: vi.fn(() => true),
}));

afterEach(() => { vi.clearAllMocks(); });

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
    expect(getPublicLoginFallback()).toBe('/');
  });

  it('keeps the public commerce implementation and exposes no website routes through the application adapter', () => {
    expect(commerceExtensionEnabled).toBe(false);
    expect(renderCommerceApplicationRoutes()).toBeNull();
    expect(renderMarketingRoutes({ login: vi.fn() })).toBeNull();
  });
});
