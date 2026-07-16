import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import {
  PUBLIC_TABS as publicTabs,
  DISABLE_PUBLIC_GET_STARTED_BUTTONS as publicGetStartedButtonsDisabled,
  DISABLE_PUBLIC_LOGIN_BUTTON as publicLoginButtonDisabled,
  DISABLE_PUBLIC_PRICING_BUTTONS as publicPricingButtonsDisabled,
  ENABLE_ORGANIZATION_CREATION as publicOrganizationCreationEnabled,
  ENABLE_LEGACY_ADMIN_IMPERSONATION_BANNER as publicLegacyImpersonationBannerEnabled,
  SHOW_PUBLIC_GET_STARTED_BUTTONS as publicGetStartedButtons,
  SHOW_PUBLIC_LOGIN_BUTTON as publicLoginButton,
  SHOW_PUBLIC_PRICING_BUTTONS as publicPricingButtons,
  WALLET_SELECTION_ALLOWED_WALLET_IDS as publicWalletSelectionAllowedWalletIds,
} from '../publicConfig.public';
import {
  PUBLIC_TABS as selfhostTabs,
  DISABLE_PUBLIC_GET_STARTED_BUTTONS as selfhostGetStartedButtonsDisabled,
  DISABLE_PUBLIC_LOGIN_BUTTON as selfhostLoginButtonDisabled,
  DISABLE_PUBLIC_PRICING_BUTTONS as selfhostPricingButtonsDisabled,
  ENABLE_ORGANIZATION_CREATION as selfhostOrganizationCreationEnabled,
  ENABLE_LEGACY_ADMIN_IMPERSONATION_BANNER as selfhostLegacyImpersonationBannerEnabled,
  SHOW_PUBLIC_GET_STARTED_BUTTONS as selfhostGetStartedButtons,
  SHOW_PUBLIC_LOGIN_BUTTON as selfhostLoginButton,
  SHOW_PUBLIC_PRICING_BUTTONS as selfhostPricingButtons,
  WALLET_SELECTION_ALLOWED_WALLET_IDS as selfhostWalletSelectionAllowedWalletIds,
  getSelfhostPublicTabs,
  getSelfhostPublicUiFlags,
  isSelfhostProductionPublicHost,
} from '../publicConfig.selfhost';

vi.mock('../publicSite.public', () => ({
  getPublicLoginFallback: () => '/',
  renderPublicRoot: () => <div>Original landing page</div>,
  renderMarketingRoutes: () => null,
}));

import { getPublicLoginFallback, renderPublicRoot } from '../publicSite.selfhost';

function renderSelfhostRoot(authState: {
  isAuthenticated: boolean;
  isAdministrator: boolean;
  isVendor: boolean;
  isApplicant: boolean;
}) {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={renderPublicRoot(authState)} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('publicSite.selfhost', () => {
  it('keeps login enabled and disables marketing CTAs only on the production host', () => {
    const expectedPublicPaths = ['/', '/product', '/solutions', '/developers', '/standards', '/demos', '/resources', '/pricing'];
    const publicResourcesTab = publicTabs.find((tab) => tab.path === '/resources');
    const selfhostResourcesTab = selfhostTabs.find((tab) => tab.path === '/resources');

    expect(publicLoginButton).toBe(true);
    expect(publicLoginButtonDisabled).toBe(false);
    expect(publicGetStartedButtons).toBe(true);
    expect(publicGetStartedButtonsDisabled).toBe(false);
    expect(publicPricingButtons).toBe(true);
    expect(publicPricingButtonsDisabled).toBe(false);
    expect(publicLegacyImpersonationBannerEnabled).toBe(false);
    expect(publicOrganizationCreationEnabled).toBe(true);
    expect(publicWalletSelectionAllowedWalletIds).toBeNull();
    expect(publicTabs.map((tab) => tab.path)).toEqual(expectedPublicPaths);
    expect(publicResourcesTab?.prefixes).toEqual(expect.arrayContaining(['/privacy-policy', '/privacy', '/terms-of-service', '/terms']));

    expect(isSelfhostProductionPublicHost('elevenidllc.com')).toBe(true);
    expect(isSelfhostProductionPublicHost('www.elevenidllc.com')).toBe(true);
    expect(isSelfhostProductionPublicHost('beta.elevenidllc.com')).toBe(false);

    expect(selfhostLoginButton).toBe(true);
    expect(selfhostLoginButtonDisabled).toBe(false);
    expect(selfhostGetStartedButtons).toBe(true);
    expect(selfhostGetStartedButtonsDisabled).toBe(false);
    expect(selfhostPricingButtons).toBe(true);
    expect(selfhostPricingButtonsDisabled).toBe(false);
    expect(selfhostLegacyImpersonationBannerEnabled).toBe(false);
    expect(selfhostOrganizationCreationEnabled).toBe(false);
    expect(selfhostWalletSelectionAllowedWalletIds).toEqual(['wr-spruce-001', 'wr-marty-001']);
    expect(selfhostTabs.map((tab) => tab.path)).toEqual(expectedPublicPaths);
    expect(selfhostTabs).toEqual(publicTabs);
    expect(selfhostResourcesTab?.prefixes).toEqual(expect.arrayContaining(['/privacy-policy', '/privacy', '/terms-of-service', '/terms']));

    expect(getSelfhostPublicUiFlags('elevenidllc.com')).toEqual({
      showPublicLoginButton: true,
      disablePublicLoginButton: false,
      showPublicGetStartedButtons: true,
      disablePublicGetStartedButtons: true,
      showPublicPricingButtons: true,
      disablePublicPricingButtons: true,
      enableLegacyAdminImpersonationBanner: false,
    });
    expect(getSelfhostPublicTabs('elevenidllc.com')).toEqual(
      publicTabs.map((tab) => (tab.path === '/pricing' ? { ...tab, disabled: true } : tab)),
    );

    expect(getSelfhostPublicUiFlags('beta.elevenidllc.com')).toEqual({
      showPublicLoginButton: true,
      disablePublicLoginButton: false,
      showPublicGetStartedButtons: true,
      disablePublicGetStartedButtons: false,
      showPublicPricingButtons: true,
      disablePublicPricingButtons: false,
      enableLegacyAdminImpersonationBanner: false,
    });
    expect(getSelfhostPublicTabs('beta.elevenidllc.com')).toEqual(publicTabs);
  });

  it('renders the original landing page when unauthenticated', () => {
    renderSelfhostRoot({
      isAuthenticated: false,
      isAdministrator: false,
      isVendor: false,
      isApplicant: false,
    });

    expect(screen.getByText('Original landing page')).toBeInTheDocument();
  });

  it('matches the public login fallback', () => {
    expect(getPublicLoginFallback()).toBe('/');
  });

  it.each([
    {
      label: 'administrator',
      authState: {
        isAuthenticated: true,
        isAdministrator: true,
        isVendor: false,
        isApplicant: false,
      },
    },
    {
      label: 'vendor',
      authState: {
        isAuthenticated: true,
        isAdministrator: false,
        isVendor: true,
        isApplicant: false,
      },
    },
    {
      label: 'applicant',
      authState: {
        isAuthenticated: true,
        isAdministrator: false,
        isVendor: false,
        isApplicant: true,
      },
    },
  ])('renders the original landing page for authenticated $label users', ({ authState }) => {
    renderSelfhostRoot({
      ...authState,
    });

    expect(screen.getByText('Original landing page')).toBeInTheDocument();
  });
});
