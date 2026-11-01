import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import AppShell from './AppShell';
import { AuthProvider } from '../../contexts/AuthContext';
import { BrandingContext } from '../../contexts/BrandingContext';
import * as handoff from '../../application/routing/appHandoff';

vi.mock('../../utils/analytics', () => ({ initAnalytics: vi.fn(), trackPageView: vi.fn(), trackWebVitals: vi.fn() }));
vi.mock('../../components/common', () => ({ NotificationBell: () => null, LanguageSwitcher: () => null }));
vi.mock('react-i18next', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-i18next')>(),
  useTranslation: () => ({ t: (key: string, fallback?: string) => fallback || key, i18n: { language: 'en' } }),
}));
vi.mock('@ui-public-config', async (importOriginal) => ({
  ...await importOriginal<Record<string, unknown>>(),
  DISABLE_PUBLIC_LOGIN_BUTTON: false,
  SHOW_PUBLIC_LOGIN_BUTTON: true,
}));

const original = window.location.href;
const alias = 'https://203.0.113.10:8443';
const canonical = 'https://marty.example.com:8443';
function shell() {
  return render(<MemoryRouter><AuthProvider><BrandingContext.Provider value={{ branding: { appName: 'Actual brand' }, isLoading: false } as any}>
    <AppShell><h1>Actual landing content</h1></AppShell>
  </BrandingContext.Provider></AuthProvider></MemoryRouter>);
}
beforeEach(() => {
  (globalThis as any).jsdom.reconfigure({ url: `${alias}/` });
  (window as any).__MARTY_RUNTIME_CONFIG__ = { hosting: { canonicalOrigin: canonical, publicEntryOrigins: [alias] } };
});
afterEach(() => {
  vi.restoreAllMocks();
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
  (globalThis as any).jsdom.reconfigure({ url: original });
});

describe('shipped public-entry actions', () => {
  it('renders a real canonical Console link and preserves the existing sign-in action without an IP session', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    const navigate = vi.spyOn(handoff, 'redirectBrowser').mockReturnValue(true);
    shell();
    expect(screen.getByRole('link', { name: 'Console' })).toHaveAttribute('href', `${canonical}/console`);
    expect(screen.getByTestId('public-entry-console')).toBeVisible();
    await userEvent.click(screen.getByTestId('login-button'));
    expect(navigate).toHaveBeenCalledWith(expect.stringMatching(/^https:\/\/marty\.example\.com:8443\/v1\/auth\/login\?/), { replace: false });
    expect(fetch).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /register|sign up/i })).not.toBeInTheDocument();
  });
  it('does not add the alias Console control on the canonical origin', () => {
    (globalThis as any).jsdom.reconfigure({ url: `${canonical}/` });
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ authenticated: false, user: null })));
    shell();
    expect(screen.queryByTestId('public-entry-console')).not.toBeInTheDocument();
  });
});
