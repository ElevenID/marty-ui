import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInstance } from 'i18next';
import { Route, Routes } from 'react-router';
import { renderWithRouter, screen } from '@test/utils';
import TrustProfileDetailPage from '../TrustProfileDetailPage';

const { getProfile, listIssuers, getWalletCompatibility } = vi.hoisted(() => ({
  getProfile: vi.fn(),
  listIssuers: vi.fn(),
  getWalletCompatibility: vi.fn(),
}));

vi.mock('../../../../services/presentationPolicyApi', () => ({
  getTrustProfile: getProfile,
  listTrustProfileIssuers: listIssuers,
  addTrustProfileIssuer: vi.fn(),
  getTrustProfileWalletCompatibility: getWalletCompatibility,
}));

function renderPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/console/org/trust/profiles/:id" element={<TrustProfileDetailPage />} />
      <Route path="/console/org/templates/credentials" element={<h1>Credential template inventory</h1>} />
    </Routes>,
    { initialEntries: ['/console/org/trust/profiles/profile-1'] },
  );
}

describe('Trust profile wallet guidance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getProfile.mockResolvedValue({
      id: 'profile-1', organization_id: 'org-1', name: 'Campus trust', status: 'active',
      supported_formats: ['SD_JWT_VC'], trust_sources: [],
    });
    listIssuers.mockResolvedValue([]);
    getWalletCompatibility.mockRejectedValue(new Error('Unsupported native route'));
  });

  it('does not request the unsupported profile endpoint or claim wallet compatibility after its failure', async () => {
    renderPage();
    await screen.findByRole('heading', { name: 'Campus trust' });
    expect(getWalletCompatibility).not.toHaveBeenCalled();
    expect(screen.queryByText('Compatible with standard-compliant wallets')).not.toBeInTheDocument();
    expect(screen.getByText(/Wallet profiles are available on credential templates/)).toBeInTheDocument();
  });

  it('does not turn profile-supported formats or an obsolete response into verified wallet claims', async () => {
    getWalletCompatibility.mockResolvedValue({
      supported_formats: ['SD_JWT_VC'], supported_wallets: [{ name: 'Unverified wallet' }],
    });
    renderPage();
    await screen.findByRole('heading', { name: 'Campus trust' });
    expect(screen.queryByText('Unverified wallet')).not.toBeInTheDocument();
    expect(screen.queryByText('Compatible Wallet Applications')).not.toBeInTheDocument();
    expect(screen.getByText(/derived configuration does not prove interoperability or successful delivery/)).toBeInTheDocument();
  });

  it('opens the credential template inventory where supported wallet profiles can be inspected', async () => {
    const { user } = renderPage();
    await screen.findByRole('heading', { name: 'Campus trust' });
    const link = screen.getByRole('link', { name: 'View credential templates' });
    expect(link).toHaveAttribute('href', '/console/org/templates/credentials');
    await user.click(link);
    expect(await screen.findByRole('heading', { name: 'Credential template inventory' })).toBeInTheDocument();
    expect(listIssuers).toHaveBeenCalledWith('profile-1', 'org-1');
  });

  it.each(['en', 'de', 'es', 'fr', 'ja', 'nl'])('provides the new guidance and destination label in %s without fallback', async (locale) => {
    const messages = JSON.parse(readFileSync(
      resolve('public', 'locales', locale, 'console.json'), 'utf8',
    ));
    const translations = createInstance();
    await translations.init({ lng: locale, fallbackLng: false, resources: { [locale]: { console: messages } } });
    for (const suffix of ['credentialWalletGuidance', 'viewCredentialTemplates']) {
      const key = `trust.trustProfileDetail.${suffix}`;
      expect(translations.exists(key, { ns: 'console' })).toBe(true);
      expect(translations.t(key, { ns: 'console' })).not.toBe(key);
    }
  });
});
