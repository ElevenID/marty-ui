import { Suspense } from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../components/pages/LegalPages', () => ({
  PrivacyPolicyPage: () => <div>Privacy policy content</div>,
  TermsOfServicePage: () => <div>Terms of service content</div>,
}));

vi.mock('../../components/pages/VerifiableCredentialApiPage', () => ({
  default: () => <div>Verification API content</div>,
}));

vi.mock('../../components/pages/OpenBadgesIssuancePage', () => ({
  default: () => <div>Open Badges issuance content</div>,
}));

import { renderMarketingRoutes } from '../publicSite.public';

function renderMarketingRoute(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Suspense fallback={<div>Loading</div>}>
        <Routes>{renderMarketingRoutes({ login: vi.fn() })}</Routes>
      </Suspense>
    </MemoryRouter>,
  );
}

describe('publicSite.public legal routes', () => {
  it.each([
    ['/privacy-policy', 'Privacy policy content'],
    ['/privacy', 'Privacy policy content'],
    ['/terms-of-service', 'Terms of service content'],
    ['/terms', 'Terms of service content'],
  ])('renders %s', async (path, expectedText) => {
    renderMarketingRoute(path);

    expect(await screen.findByText(expectedText)).toBeInTheDocument();
  });
});

describe('publicSite.public product aliases', () => {
  it.each([
    ['/verification', 'Verification API content'],
    ['/issuance', 'Open Badges issuance content'],
  ])('routes %s to canonical product content', async (path, expectedText) => {
    renderMarketingRoute(path);

    expect(await screen.findByText(expectedText)).toBeInTheDocument();
  });
});
