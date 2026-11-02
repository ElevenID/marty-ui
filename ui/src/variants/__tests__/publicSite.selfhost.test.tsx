import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';

import * as publicConfig from '../publicConfig.public';
import * as customerConfig from '../publicConfig.selfhost';
import { getPublicLoginFallback, renderMarketingRoutes, renderPublicRoot } from '../publicSite.selfhost';

const originalUrl = window.location.href;

// Importing the production route module is itself a customer build regression.
vi.mock('../publicSite.public', () => {
  throw new Error('Customer UI must not import production marketing routes');
});

afterEach(() => {
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

  it('renders an application entry with links to the enabled customer experiences', () => {
    render(renderPublicRoot());
    expect(screen.getByRole('heading', { name: 'Application portal' })).toBeVisible();
    expect(screen.getByRole('link', { name: 'Open console' })).toHaveAttribute('href', '/console');
    expect(screen.getByRole('link', { name: 'View applications' })).toHaveAttribute('href', '/apply');
    expect(getPublicLoginFallback()).toBe('/console');
  });

  it('does not advertise a console excluded at startup', () => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: ['public'] } };
    render(renderPublicRoot());
    expect(screen.queryByRole('link', { name: 'Open console' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'View applications' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View organizations' })).toHaveAttribute('href', '/organizations');
    expect(getPublicLoginFallback()).toBe('/');
  });

  it('hands customer application actions from the IP entry to the configured DNS origin', () => {
    const alias = 'https://203.0.113.10:8443';
    const canonical = 'https://customer.example:8443';
    (globalThis as any).jsdom.reconfigure({ url: `${alias}/` });
    (window as any).__MARTY_RUNTIME_CONFIG__ = {
      web: { enabled_sections: ['public', 'console'] },
      hosting: { canonicalOrigin: canonical, publicEntryOrigins: [alias] },
    };
    render(renderPublicRoot());
    expect(screen.getByRole('link', { name: 'Open console' })).toHaveAttribute('href', `${canonical}/console`);
    expect(screen.getByRole('link', { name: 'View applications' })).toHaveAttribute('href', `${canonical}/apply`);
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
