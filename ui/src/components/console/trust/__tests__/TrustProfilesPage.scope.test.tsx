import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInstance } from 'i18next';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { useLayoutEffect } from 'react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { act, fireEvent, renderWithRouter, renderWithoutRouter, screen, waitFor, within } from '@test/utils';
import TrustProfilesPage from '../TrustProfilesPage';
import TrustProfileDetailPage from '../TrustProfileDetailPage';

const { listProfiles, listRevocationProfiles, listIdentities, getProfile, listIssuers, context, permissions, grants } = vi.hoisted(() => ({
  listProfiles: vi.fn(), listRevocationProfiles: vi.fn(), listIdentities: vi.fn(), getProfile: vi.fn(), listIssuers: vi.fn(),
  context: { activeOrgId: 'org-1' as string | null }, permissions: { isLoading: false }, grants: new Set<string>(),
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permissions, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  listTrustProfiles: listProfiles, listRevocationProfiles,
  getTrustProfile: getProfile, listTrustProfileIssuers: listIssuers, addTrustProfileIssuer: vi.fn(),
}));
vi.mock('../../../../services/issuerIdentitiesApi', () => ({ listPublicIssuerIdentities: listIdentities }));

let navigateTo: ReturnType<typeof useNavigate>;
function NavigationProbe() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route">{location.pathname}{location.search}</output>;
}
function page() {
  return <><NavigationProbe /><Routes>
    <Route path="/console/org/trust/profiles" element={<TrustProfilesPage />} />
    <Route path="/console/org/trust/profiles/new" element={<h1>Create profile destination</h1>} />
    <Route path="/console/org/trust/profiles/:id" element={<TrustProfileDetailPage />} />
    <Route path="/console/org/trust/profiles/:id/edit" element={<h1>Edit profile destination</h1>} />
    <Route path="/elsewhere" element={<h1>Another page</h1>} />
  </Routes></>;
}
function renderPage() {
  return renderWithRouter(page(), { initialEntries: ['/console/org/trust/profiles'] });
}
function profile(id = 'profile-1', organizationId = 'org-1') {
  return { id, organization_id: organizationId, name: 'Profile ' + id, profile_type: 'CUSTOM',
    status: 'ACTIVE', trust_sources: [], allowed_algorithms: ['ES256'], supported_formats: ['SD_JWT_VC'],
    updated_at: '2026-11-01T10:00:00Z' };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => { resolve = yes; });
  return { promise, resolve };
}
const fullPage = () => Array.from({ length: 100 }, (_, i) => profile('old-' + i));

beforeEach(() => {
  vi.clearAllMocks();
  window.history.replaceState({}, '', '/');
  context.activeOrgId = 'org-1'; permissions.isLoading = false;
  grants.clear();
  for (const grant of ['trust-profile:view', 'trust-profile:create', 'trust-profile:edit', 'trusted-issuer:view']) grants.add(grant);
  listProfiles.mockReset().mockResolvedValue([]);
  listRevocationProfiles.mockReset().mockResolvedValue([]);
  listIdentities.mockReset().mockResolvedValue({ identities: [] });
  getProfile.mockReset().mockResolvedValue(profile());
  listIssuers.mockReset().mockResolvedValue([]);
});

describe('Trust Profile catalog scope and native inventory', () => {
  it.each(['loading grants', 'no organization', 'missing view'])('does not load or expose creation with %s', async (condition) => {
    if (condition === 'loading grants') permissions.isLoading = true;
    if (condition === 'no organization') context.activeOrgId = null;
    if (condition === 'missing view') grants.delete('trust-profile:view');
    renderPage();
    await act(async () => {});
    expect(listProfiles).not.toHaveBeenCalled();
    expect(listRevocationProfiles).not.toHaveBeenCalled();
    expect(listIdentities).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /build/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /create trust profile/i })).not.toBeInTheDocument();
  });

  it('keeps the real empty-state creation link enabled without unrelated issuer or revocation configuration', async () => {
    const { user } = renderPage();
    const create = await screen.findByRole('link', { name: /create trust profile/i });
    expect(create).not.toHaveAttribute('aria-disabled', 'true');
    expect(create).toHaveAttribute('href', '/console/org/trust/profiles/new');
    expect(listIdentities).not.toHaveBeenCalled();
    expect(listRevocationProfiles).not.toHaveBeenCalled();
    await user.click(create);
    expect(await screen.findByRole('heading', { name: 'Create profile destination' })).toBeInTheDocument();
  });

  it('shows readable inventory without create or edit controls when those grants are absent', async () => {
    grants.delete('trust-profile:create'); grants.delete('trust-profile:edit');
    listProfiles.mockResolvedValue([profile()]);
    renderPage();
    await screen.findByText('Profile profile-1');
    expect(screen.queryByRole('button', { name: /build/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^edit$/i })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /view details/i })).toBeInTheDocument();
    expect(listIdentities).not.toHaveBeenCalled();
    expect(listRevocationProfiles).not.toHaveBeenCalled();
  });

  it('does not offer an empty-state create action to a view-only user', async () => {
    grants.delete('trust-profile:create');
    renderPage();
    await screen.findByText(/no trust profiles/i);
    expect(screen.queryByRole('link', { name: /create trust profile/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /build/i })).not.toBeInTheDocument();
  });

  it('keeps a failed read distinct from an empty catalog and offers a real retry', async () => {
    listProfiles.mockRejectedValueOnce(new Error('Catalog temporarily unavailable'));
    const { user } = renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Catalog temporarily unavailable');
    expect(screen.queryByText(/no trust profiles/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText(/no trust profiles/i)).toBeInTheDocument();
    expect(listProfiles).toHaveBeenCalledTimes(2);
  });

  it('rejects a foreign organization record without rendering it as selectable', async () => {
    listProfiles.mockResolvedValue([profile('foreign', 'org-2')]);
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/organization|scope/i);
    expect(screen.queryByText('Profile foreign')).not.toBeInTheDocument();
  });

  it('loads all catalog pages and does not show a partial inventory while the final page is pending', async () => {
    const last = deferred<ReturnType<typeof profile>[]>();
    listProfiles.mockResolvedValueOnce(fullPage()).mockReturnValueOnce(last.promise);
    renderPage();
    await waitFor(() => expect(listProfiles).toHaveBeenCalledTimes(2));
    expect(screen.queryByText('Profile old-0')).not.toBeInTheDocument();
    await act(async () => { last.resolve([profile('last')]); });
    expect(await screen.findByText('Profile last')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(102);
    expect(listProfiles).toHaveBeenNthCalledWith(2, { organization_id: 'org-1', offset: 100, limit: 100 });
  });

  it('does not continue an old catalog after unmount', async () => {
    const old = deferred<ReturnType<typeof profile>[]>();
    listProfiles.mockReturnValueOnce(old.promise);
    renderPage();
    await waitFor(() => expect(listProfiles).toHaveBeenCalledTimes(1));
    await act(async () => { navigateTo('/elsewhere'); });
    await act(async () => { old.resolve(fullPage()); });
    expect(screen.getByRole('heading', { name: 'Another page' })).toBeInTheDocument();
    expect(listProfiles).toHaveBeenCalledTimes(1);
  });

  it('invalidates pending pagination when view permission is withdrawn', async () => {
    const old = deferred<ReturnType<typeof profile>[]>();
    listProfiles.mockReturnValueOnce(old.promise);
    const { rerender } = renderPage();
    await waitFor(() => expect(listProfiles).toHaveBeenCalledTimes(1));
    grants.delete('trust-profile:view'); rerender(page());
    await act(async () => { old.resolve(fullPage()); });
    expect(listProfiles).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('discards the prior organization and stops its remaining page requests', async () => {
    const old = deferred<ReturnType<typeof profile>[]>();
    listProfiles.mockReturnValueOnce(old.promise).mockResolvedValue([profile('current', 'org-2')]);
    const { rerender } = renderPage();
    await waitFor(() => expect(listProfiles).toHaveBeenCalledTimes(1));
    context.activeOrgId = 'org-2'; rerender(page());
    expect(await screen.findByText('Profile current')).toBeInTheDocument();
    await act(async () => { old.resolve(fullPage()); });
    expect(listProfiles).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('Profile old-0')).not.toBeInTheDocument();
  });

  it.each(['/elsewhere', '/console/org/trust/profiles?filter=active', '/console/org/trust/profiles'])(
    'blocks old page continuation while a newer browser entry has not committed: %s', async (nextPath) => {
      const old = deferred<ReturnType<typeof profile>[]>();
      listProfiles.mockReturnValueOnce(old.promise);
      window.history.replaceState({}, '', '/console/org/trust/profiles');
      renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
      await waitFor(() => expect(listProfiles).toHaveBeenCalledTimes(1));
      await act(async () => { navigateTo(nextPath); old.resolve(fullPage()); });
      expect(listProfiles.mock.calls.filter(([params]) => params.offset === 100)).toEqual([]);
      expect(screen.getByTestId('current-route')).toHaveTextContent(nextPath);
    },
  );

  it('shows native pinned-source and algorithm counts without claiming a relationship total', async () => {
    const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>('../../../../services/presentationPolicyApi');
    listProfiles.mockImplementation(api.listTrustProfiles);
    server.use(http.get('*/v1/trust-profiles', () => HttpResponse.json([{
      ...profile(), status: 'ARCHIVED',
      trust_sources: [{ id: 'source-1', source_type: 'PINNED_ISSUER', issuer_did: 'did:web:one.example' },
        { id: 'source-2', source_type: 'TRUST_LIST', endpoint_url: 'https://registry.example/list' }],
      allowed_algorithms: ['ES256', 'EdDSA'],
    }])));
    renderPage();
    const row = (await screen.findByText('Profile profile-1')).closest('tr')!;
    expect(screen.getByRole('columnheader', { name: /pinned issuer sources/i })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: /^trusted issuers$/i })).not.toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /allowed algorithms/i })).toBeInTheDocument();
    expect(within(row).getByText('Archived')).toBeInTheDocument();
    expect(within(row).getAllByRole('cell').map((cell) => cell.textContent)).toEqual(expect.arrayContaining(['1', '2']));
  });

  it('uses the same honest pinned-source label in detail provenance', async () => {
    getProfile.mockResolvedValue({ ...profile(), trust_sources: [
      { id: 'pinned', source_type: 'PINNED_ISSUER', issuer_did: 'did:web:pinned.example' },
      { id: 'registry', source_type: 'TRUST_LIST', issuer_did: 'did:web:registry.example' },
    ] });
    renderWithRouter(page(), { initialEntries: ['/console/org/trust/profiles/profile-1'] });
    const label = await screen.findByText('Pinned issuer sources');
    expect(label.parentElement).toHaveTextContent('1');
  });

  it.each(['en', 'de', 'es', 'fr', 'ja', 'nl'])('provides catalog messages in %s without fallback', async (locale) => {
    const messages = JSON.parse(readFileSync(resolve('public', 'locales', locale, 'console.json'), 'utf8'));
    const instance = createInstance();
    await instance.init({ lng: locale, fallbackLng: false, resources: { [locale]: { console: messages } } });
    for (const suffix of ['title', 'description', 'selectOrganization', 'readDenied', 'scopeMismatch', 'loadFailed', 'retryProfiles',
      'emptyTitle', 'emptyDescription', 'createProfile', 'pinnedSources', 'pinnedSourcesHelp', 'allowedAlgorithms',
      'name', 'framework', 'status', 'lastUpdated', 'actions', 'viewDetails', 'edit', 'consoleBreadcrumb', 'trustBreadcrumb']) {
      const key = 'trust.trustProfilesPage.' + suffix;
      expect(instance.exists(key, { ns: 'console' })).toBe(true);
      expect(instance.t(key, { ns: 'console' })).not.toBe(key);
    }
  });
});
