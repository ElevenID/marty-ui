import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';

import * as publicConfig from '../publicConfig.public';
import * as customerConfig from '../publicConfig.selfhost';
import { getPublicLoginFallback, renderMarketingRoutes, renderPublicRoot } from '../publicSite.selfhost';

import { redirectBrowser } from '../../application/routing/appHandoff';

vi.mock('../../application/routing/appHandoff', () => ({ redirectBrowser: vi.fn() }));

const originalUrl = window.location.href;

function renderCustomerRoot(isAuthenticated = false) {
  return render(
    <MemoryRouter>
      <Routes>
        <Route path="/" element={renderPublicRoot({ isAuthenticated })} />
        <Route path="/login" element={<div>Customer login</div>} />
        <Route path="/organizations" element={<div>Customer organizations</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

// Importing the production route module is itself a customer build regression.
vi.mock('../publicSite.public', () => {
  throw new Error('Customer UI must not import production marketing routes');
});

afterEach(() => {
  vi.clearAllMocks();
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
  (globalThis as any).jsdom.reconfigure({ url: originalUrl });
});

describe('customer UI variant', () => {
  it('keeps authentication and application destinations without production marketing', () => {
    expect(customerConfig.SHOW_PUBLIC_LOGIN_BUTTON).toBe(true);
    expect(customerConfig.DISABLE_PUBLIC_LOGIN_BUTTON).toBe(false);
    expect(customerConfig.SHOW_PUBLIC_GET_STARTED_BUTTONS).toBe(false);
    expect(customerConfig.SHOW_PUBLIC_PRICING_BUTTONS).toBe(false);
    expect(customerConfig.SHOW_PUBLIC_CTA).toBe(false);
    expect(customerConfig.SHOW_PUBLIC_DEMOS).toBe(false);
    expect(customerConfig.I18N_NAMESPACES).not.toContain('marketing');
    expect(customerConfig.ENABLE_ORGANIZATION_CREATION).toBe(false);
    expect(customerConfig.WALLET_SELECTION_ALLOWED_WALLET_IDS).toEqual(['wr-spruce-001', 'wr-marty-001']);
    expect(customerConfig.PUBLIC_TABS.map((tab) => tab.path)).toEqual(['/', '/console', '/apply', '/docs']);

    expect(publicConfig.SHOW_PUBLIC_DEMOS).toBe(true);
    expect(publicConfig.SHOW_PUBLIC_CTA).toBe(true);
    expect(publicConfig.PUBLIC_TABS.map((tab) => tab.path)).toContain('/product');
    expect(publicConfig.I18N_NAMESPACES).toContain('marketing');
  });

  it.each(['elevenidllc.com', 'www.elevenidllc.com', 'customer.example'])('never enables marketing based on hostname %s', (hostname) => {
    expect(customerConfig.getSelfhostPublicUiFlags(hostname)).toMatchObject({
      showPublicLoginButton: true,
      showPublicGetStartedButtons: false,
      showPublicPricingButtons: false,
    });
  });

  it('opens login for a signed-out customer instead of a homepage', () => {
    renderCustomerRoot();
    expect(screen.getByText('Customer login')).toBeVisible();
    expect(redirectBrowser).not.toHaveBeenCalled();
    expect(getPublicLoginFallback()).toBe('/console');
  });

  it('loads the console entrypoint for a signed-in customer', () => {
    renderCustomerRoot(true);
    expect(redirectBrowser).toHaveBeenCalledWith('/console', { replace: true });
    expect(screen.queryByText('Customer login')).not.toBeInTheDocument();
  });

  it.each([false, true])('respects a disabled console (authenticated=%s)', (authenticated) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: ['public'] } };
    renderCustomerRoot(authenticated);
    expect(screen.getByText(authenticated ? 'Customer organizations' : 'Customer login')).toBeVisible();
    expect(redirectBrowser).not.toHaveBeenCalled();
    expect(getPublicLoginFallback()).toBe('/organizations');
  });

  it('hands authentication from the IP entry to the configured DNS origin', () => {
    const alias = 'https://203.0.113.10:8443';
    const canonical = 'https://customer.example:8443';
    (globalThis as any).jsdom.reconfigure({ url: `${alias}/` });
    (window as any).__MARTY_RUNTIME_CONFIG__ = {
      web: { enabled_sections: ['public', 'console'] },
      hosting: { canonicalOrigin: canonical, publicEntryOrigins: [alias] },
    };
    renderCustomerRoot();
    expect(redirectBrowser).toHaveBeenCalledWith(`${canonical}/login`, { replace: true });
  });

  it.each(['/product', '/pricing', '/blog', '/authors', '/demos', '/privacy-policy'])('does not register production route %s', (pathname) => {
    render(
      <MemoryRouter initialEntries={[pathname]}>
        <Routes>
          {renderMarketingRoutes()}
          <Route path="*" element={<div>Not available</div>} />
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText('Not available')).toBeVisible();
  });
});
