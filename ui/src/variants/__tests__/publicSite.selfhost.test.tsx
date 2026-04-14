import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import {
  PUBLIC_TABS as publicTabs,
  DISABLE_PUBLIC_GET_STARTED_BUTTONS as publicGetStartedButtonsDisabled,
  DISABLE_PUBLIC_LOGIN_BUTTON as publicLoginButtonDisabled,
  DISABLE_PUBLIC_PRICING_BUTTONS as publicPricingButtonsDisabled,
  SHOW_PUBLIC_GET_STARTED_BUTTONS as publicGetStartedButtons,
  SHOW_PUBLIC_LOGIN_BUTTON as publicLoginButton,
  SHOW_PUBLIC_PRICING_BUTTONS as publicPricingButtons,
} from '../publicConfig.public';
import {
  PUBLIC_TABS as selfhostTabs,
  DISABLE_PUBLIC_GET_STARTED_BUTTONS as selfhostGetStartedButtonsDisabled,
  DISABLE_PUBLIC_LOGIN_BUTTON as selfhostLoginButtonDisabled,
  DISABLE_PUBLIC_PRICING_BUTTONS as selfhostPricingButtonsDisabled,
  SHOW_PUBLIC_GET_STARTED_BUTTONS as selfhostGetStartedButtons,
  SHOW_PUBLIC_LOGIN_BUTTON as selfhostLoginButton,
  SHOW_PUBLIC_PRICING_BUTTONS as selfhostPricingButtons,
  getSelfhostPublicTabs,
  getSelfhostPublicUiFlags,
  isSelfhostProductionPublicHost,
} from '../publicConfig.selfhost';

vi.mock('../publicSite.public', () => ({
  renderPublicRoot: () => <div>Original landing page</div>,
  renderMarketingRoutes: () => null,
}));

import { renderPublicRoot } from '../publicSite.selfhost';

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
        <Route path="/dashboard" element={<div>Admin dashboard</div>} />
        <Route path="/console/org" element={<div>Vendor console</div>} />
        <Route path="/console/applicant/catalog" element={<div>Applicant catalog</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('publicSite.selfhost', () => {
  it('disables marketing CTAs only on the production host', () => {
    const expectedPublicPaths = ['/', '/product', '/solutions', '/developers', '/standards', '/resources', '/pricing'];

    expect(publicLoginButton).toBe(true);
    expect(publicLoginButtonDisabled).toBe(false);
    expect(publicGetStartedButtons).toBe(true);
    expect(publicGetStartedButtonsDisabled).toBe(false);
    expect(publicPricingButtons).toBe(true);
    expect(publicPricingButtonsDisabled).toBe(false);
    expect(publicTabs.map((tab) => tab.path)).toEqual(expectedPublicPaths);

    expect(isSelfhostProductionPublicHost('elevenidllc.com')).toBe(true);
    expect(isSelfhostProductionPublicHost('beta.elevenidllc.com')).toBe(false);

    expect(selfhostLoginButton).toBe(true);
    expect(selfhostLoginButtonDisabled).toBe(false);
    expect(selfhostGetStartedButtons).toBe(true);
    expect(selfhostGetStartedButtonsDisabled).toBe(false);
    expect(selfhostPricingButtons).toBe(true);
    expect(selfhostPricingButtonsDisabled).toBe(false);
    expect(selfhostTabs.map((tab) => tab.path)).toEqual(expectedPublicPaths);
    expect(selfhostTabs).toEqual(publicTabs);

    expect(getSelfhostPublicUiFlags('elevenidllc.com')).toEqual({
      showPublicLoginButton: true,
      disablePublicLoginButton: true,
      showPublicGetStartedButtons: true,
      disablePublicGetStartedButtons: true,
      showPublicPricingButtons: true,
      disablePublicPricingButtons: true,
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

  it('redirects authenticated administrators to the dashboard', () => {
    renderSelfhostRoot({
      isAuthenticated: true,
      isAdministrator: true,
      isVendor: false,
      isApplicant: false,
    });

    expect(screen.getByText('Admin dashboard')).toBeInTheDocument();
  });
});