import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInstance } from 'i18next';
import { useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithRouter, renderWithoutRouter, screen } from '@test/utils';
import RevocationProfileDetailPage from '../RevocationProfileDetailPage';

const { getProfile, activateProfile, context, permission, grants } = vi.hoisted(() => ({
  getProfile: vi.fn(), activateProfile: vi.fn(),
  context: { activeOrgId: 'org-1' as string | null },
  permission: { isLoading: false }, grants: new Set<string>(),
}));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  getRevocationProfile: getProfile, activateRevocationProfile: activateProfile,
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));

const ID = '11111111-1111-4111-8111-111111111111';
const NEXT_ID = '22222222-2222-4222-8222-222222222222';
const PATH = '/console/org/trust/revocation/' + ID;
const NEXT_PATH = '/console/org/trust/revocation/' + NEXT_ID;
// Exact public HTTP ProfileResponse shape, not internal VerifierRevocationConfig.
const profile = (overrides: Record<string, unknown> = {}) => ({
  id: ID, organization_id: 'org-1', name: 'Native revocation policy', status: 'DRAFT',
  revocation_mechanism: ['STATUS_LIST_2021', 'BITSTRING_STATUS_LIST', 'TOKEN_STATUS_LIST', 'OCSP', 'CRL'],
  mechanism_priority: ['OCSP', 'BITSTRING_STATUS_LIST', 'CRL'], check_mode: 'ALWAYS',
  issuer_config: { auto_allocate_index: true, batch_update_interval_seconds: 600, list_size: 131072, uri_template: 'https://status.example.com/tenant-a' },
  status_list_url: 'https://status.example.com/tenant-a/v1/organizations/org-1/revocation-profiles/' + ID + '/status-lists/{mechanism}/{purpose}',
  created_at: '2024-01-15T10:00:00+00:00', updated_at: '2024-06-01T12:00:00+00:00',
  ...overrides,
});
function deferred<T = unknown>() {
  let resolve!: (value: T) => void; let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
let navigateTo: ReturnType<typeof useNavigate>;
function NavigationDriver() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route">{location.pathname}{location.search}{location.hash}</output>;
}
function page() {
  return <><NavigationDriver /><Routes>
    <Route path="/console/org/trust/revocation/:id" element={<RevocationProfileDetailPage />} />
    <Route path="/console/org/trust/revocation" element={<h1>Revocation inventory</h1>} />
    <Route path="/elsewhere" element={<h1>Another page</h1>} />
  </Routes></>;
}
function renderPage() { return renderWithRouter(page(), { initialEntries: [PATH] }); }
async function activate() { fireEvent.click(await screen.findByRole('button', { name: /^activate$/i })); }
async function useNativeAdapter() {
  const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>('../../../../services/presentationPolicyApi');
  getProfile.mockImplementation(api.getRevocationProfile);
  activateProfile.mockImplementation(api.activateRevocationProfile);
}
beforeEach(() => {
  vi.clearAllMocks(); window.history.replaceState({}, '', '/');
  context.activeOrgId = 'org-1'; permission.isLoading = false; grants.clear();
  grants.add('revocation-profile:view'); grants.add('revocation-profile:activate');
  getProfile.mockReset().mockResolvedValue(profile());
  activateProfile.mockReset().mockResolvedValue(profile({ status: 'ACTIVE' }));
});
afterEach(() => { vi.restoreAllMocks(); });

describe('Revocation detail native readback', () => {
  it('renders the scoped native profile, endpoint template, mechanisms and breadcrumbs', async () => {
    renderPage(); await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(getProfile).toHaveBeenCalledWith(ID);
    expect(screen.getByText(profile().status_list_url)).toBeInTheDocument();
    for (const name of ['Status List 2021', 'Bitstring Status List', 'Token Status List', 'OCSP', 'CRL']) {
      expect(screen.getByText(name, { exact: true })).toBeInTheDocument();
    }
    expect(screen.getByRole('link', { name: 'Revocation Profiles' })).toHaveAttribute('href', '/console/org/trust/revocation');
  });

  it.each([
    ['ALWAYS', {}, undefined, undefined],
    ['CACHED', { cache_ttl_seconds: 600 }, '600s', undefined],
    ['OFFLINE_GRACE', { offline_grace_seconds: 7200 }, undefined, '7200s'],
    ['DISABLED', {}, undefined, undefined],
  ])('uses actual HTTP timing and conditional metadata through the API adapter: %s', async (mode, fields, cache, grace) => {
    await useNativeAdapter();
    server.use(http.get('*/v1/revocation-profiles/:id', () => HttpResponse.json(profile({ check_mode: mode, ...fields }))));
    renderPage(); await screen.findByRole('heading', { name: 'Native revocation policy' });
    if (cache) expect(screen.getByText(cache)).toBeInTheDocument();
    else expect(screen.queryByText('Cache TTL')).not.toBeInTheDocument();
    if (grace) expect(screen.getByText(grace)).toBeInTheDocument();
    else expect(screen.queryByText('Offline grace period')).not.toBeInTheDocument();
    expect(screen.queryByText(/soft.fail mode|hard fail/i)).not.toBeInTheDocument();
    if (mode === 'DISABLED') expect(screen.getByRole('alert')).toHaveTextContent(/status checking is disabled/i);
    else expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('ignores internal or legacy fields absent from ProfileResponse and mode-inapplicable durations', async () => {
    getProfile.mockResolvedValue(profile({ check_mode: 'ALWAYS', revocation_mechanism: [], status_list_url: '',
      mechanisms: ['Legacy mechanism'], status_list_endpoint: 'https://obsolete.example/status',
      description: 'Unreturned description', grace_period_seconds: 123, cache_ttl_seconds: 456, offline_grace_seconds: 789 }));
    renderPage(); await screen.findByRole('heading', { name: 'Native revocation policy' });
    for (const value of ['Legacy mechanism', 'https://obsolete.example/status', 'Unreturned description', '123s', '456s', '789s']) {
      expect(screen.queryByText(value)).not.toBeInTheDocument();
    }
  });

  it.each([undefined, 'HARD_FAIL', 'SOFT_FAIL', 'SKIP', 'FUTURE_MODE'])('does not turn unknown HTTP timing %s into ALWAYS or internal failure semantics', async (check_mode) => {
    getProfile.mockResolvedValue(profile({ check_mode })); renderPage();
    await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(screen.getAllByText(/unknown check policy/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/checked for every verification/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/soft.fail mode|hard fail|always check/i)).not.toBeInTheDocument();
  });

  it.each([undefined, 'FUTURE_STATUS'])('does not invent Draft or enable activation for unknown lifecycle %s', async (status) => {
    getProfile.mockResolvedValue(profile({ status })); renderPage();
    await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(screen.getByText(/unknown status/i)).toBeInTheDocument();
    expect(screen.queryByText(/^draft$/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
  });

  it('keeps an unknown mechanism visible without assigning it a known protocol description', async () => {
    getProfile.mockResolvedValue(profile({ revocation_mechanism: ['FUTURE_MECHANISM'] })); renderPage();
    await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(screen.getByText('FUTURE_MECHANISM')).toBeInTheDocument();
    expect(screen.getByText(/unrecognized revocation mechanism/i)).toBeInTheDocument();
  });
});

describe('Revocation detail organization and native grants', () => {
  it.each(['organization', 'permissions-loading', 'view'])('does not read or expose actions without current %s', async (missing) => {
    if (missing === 'organization') context.activeOrgId = null;
    if (missing === 'permissions-loading') permission.isLoading = true;
    if (missing === 'view') grants.delete('revocation-profile:view');
    renderPage(); await act(async () => {});
    expect(getProfile).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
  });

  it('requires the activate grant independently of view and edit', async () => {
    grants.delete('revocation-profile:activate'); grants.add('revocation-profile:edit');
    renderPage(); await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
  });

  it.each([{ id: NEXT_ID }, { id: undefined }, { organization_id: 'org-2' }, { organization_id: undefined }])('rejects an out-of-scope profile before showing its details: %j', async (wrong) => {
    getProfile.mockResolvedValue(profile(wrong)); renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/requested profile.*selected organization/i);
    expect(screen.queryByRole('heading', { name: 'Native revocation policy' })).not.toBeInTheDocument();
    expect(screen.queryByText(profile().status_list_url)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
  });

  it.each(['organization', 'profile', 'query', 'entry', 'hash'])('discards a late profile result when the %s changes', async (change) => {
    const old = deferred();
    getProfile.mockReturnValueOnce(old.promise).mockResolvedValue(profile({ id: change === 'profile' ? NEXT_ID : ID,
      organization_id: change === 'organization' ? 'org-2' : 'org-1', name: 'Current profile' }));
    const view = renderPage(); await waitFor(() => expect(getProfile).toHaveBeenCalledTimes(1));
    if (change === 'organization') { context.activeOrgId = 'org-2'; view.rerender(page()); }
    else await act(async () => { await navigateTo(change === 'profile' ? NEXT_PATH : PATH + (change === 'query' ? '?review=next' : change === 'hash' ? '#next' : '')); });
    await screen.findByRole('heading', { name: 'Current profile' });
    await act(async () => { old.resolve(profile({ name: 'Obsolete profile' })); });
    expect(screen.queryByText('Obsolete profile')).not.toBeInTheDocument();
  });

  it('withdraws a pending read when principal grants are reloading and does not restore its error', async () => {
    const old = deferred(); getProfile.mockReturnValueOnce(old.promise);
    const view = renderPage(); await waitFor(() => expect(getProfile).toHaveBeenCalledTimes(1));
    permission.isLoading = true; view.rerender(page());
    await act(async () => { old.reject(new Error('Obsolete account error')); });
    expect(screen.queryByText('Obsolete account error')).not.toBeInTheDocument();
    permission.isLoading = false; getProfile.mockResolvedValue(profile({ name: 'Current account profile' })); view.rerender(page());
    await screen.findByRole('heading', { name: 'Current account profile' });
  });

  it('keeps the current load error and provides a working retry', async () => {
    getProfile.mockRejectedValueOnce(new Error('Current service unavailable')).mockResolvedValueOnce(profile());
    const { user } = renderPage(); expect(await screen.findByRole('alert')).toHaveTextContent('Current service unavailable');
    await user.click(screen.getByRole('button', { name: 'Retry profile' }));
    await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(getProfile).toHaveBeenCalledTimes(2);
  });
});

describe('Revocation activation current action and native postimage', () => {
  it.each(['DRAFT', 'SUSPENDED'])('activates native %s through the actual API and uses its postimage without another GET', async (status) => {
    await useNativeAdapter(); let reads = 0; let writes = 0;
    const updated = '2026-11-09T15:31:12+00:00';
    server.use(
      http.get('*/v1/revocation-profiles/:id', () => { reads++; return HttpResponse.json(profile({ status })); }),
      http.post('*/v1/revocation-profiles/:id/activate', async ({ request, params }) => {
        writes++; expect(params.id).toBe(ID); expect(await request.json()).toEqual({});
        return HttpResponse.json(profile({ status: 'ACTIVE', name: 'Activated native profile', updated_at: updated }));
      }),
    );
    renderPage(); await activate();
    await screen.findByRole('heading', { name: 'Activated native profile' });
    expect(screen.getByText(new Date(updated).toLocaleString())).toBeInTheDocument();
    expect(screen.getByText(/^active$/i)).toBeInTheDocument();
    expect(reads).toBe(1); expect(writes).toBe(1);
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
  });

  it('does not dispatch activation for an already active profile', async () => {
    getProfile.mockResolvedValue(profile({ status: 'ACTIVE' })); renderPage();
    await screen.findByRole('heading', { name: 'Native revocation policy' });
    expect(screen.queryByRole('button', { name: /^activate$/i })).not.toBeInTheDocument();
    expect(activateProfile).not.toHaveBeenCalled();
  });

  it('locks duplicate activation synchronously and leaves the pending action visible', async () => {
    const write = deferred(); activateProfile.mockReturnValue(write.promise); renderPage();
    const button = await screen.findByRole('button', { name: /^activate$/i });
    act(() => { fireEvent.click(button); fireEvent.click(button); });
    expect(activateProfile).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: /activating/i })).toBeDisabled();
    await act(async () => { write.resolve(profile({ status: 'ACTIVE' })); });
    expect(await screen.findByText(/^active$/i)).toBeInTheDocument(); expect(getProfile).toHaveBeenCalledTimes(1);
  });

  it('retains the current action error and retries only after another click', async () => {
    activateProfile.mockRejectedValueOnce(new Error('Current activation rejected')).mockResolvedValueOnce(profile({ status: 'ACTIVE' }));
    renderPage(); await activate();
    expect(await screen.findByRole('alert')).toHaveTextContent('Current activation rejected');
    expect(screen.getByRole('button', { name: /^activate$/i })).toBeEnabled();
    expect(activateProfile).toHaveBeenCalledTimes(1); await activate();
    expect(await screen.findByText(/^active$/i)).toBeInTheDocument();
    expect(activateProfile).toHaveBeenCalledTimes(2); expect(getProfile).toHaveBeenCalledTimes(1);
  });

  it.each([{ id: NEXT_ID }, { organization_id: 'org-2' }, { status: 'DRAFT' }, { status: 'SUSPENDED' }, { status: undefined }])('refuses a nonmatching ACTIVE postimage and retains the current profile: %j', async (wrong) => {
    activateProfile.mockResolvedValue(profile({ status: 'ACTIVE', name: 'Unconfirmed postimage', ...wrong }));
    renderPage(); await activate();
    expect(await screen.findByRole('alert')).toHaveTextContent(/activation response.*active.*requested profile.*selected organization/i);
    expect(screen.getByRole('heading', { name: 'Native revocation policy' })).toBeInTheDocument();
    expect(screen.queryByText('Unconfirmed postimage')).not.toBeInTheDocument();
    expect(getProfile).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: /^activate$/i })).toBeEnabled();
  });

  it.each(['organization', 'profile', 'query', 'entry', 'activate-grant', 'view-grant'])('does not apply an old activation after the %s changes', async (change) => {
    const write = deferred(); activateProfile.mockReturnValueOnce(write.promise);
    const view = renderPage(); await activate();
    getProfile.mockResolvedValue(profile({ id: change === 'profile' ? NEXT_ID : ID,
      organization_id: change === 'organization' ? 'org-2' : 'org-1', name: 'Current profile' }));
    if (change === 'organization') { context.activeOrgId = 'org-2'; view.rerender(page()); }
    else if (change.endsWith('-grant')) { grants.delete('revocation-profile:' + change.split('-')[0]); view.rerender(page()); }
    else await act(async () => { await navigateTo(change === 'profile' ? NEXT_PATH : PATH + (change === 'query' ? '?review=next' : '')); });
    if (change !== 'view-grant') await screen.findByRole('heading', { name: 'Current profile' });
    const readCount = getProfile.mock.calls.length;
    await act(async () => { write.resolve(profile({ status: 'ACTIVE', name: 'Obsolete activation' })); });
    expect(screen.queryByText('Obsolete activation')).not.toBeInTheDocument();
    expect(getProfile).toHaveBeenCalledTimes(readCount);
    if (change !== 'view-grant') expect(screen.getByRole('heading', { name: 'Current profile' })).toBeInTheDocument();
  });

  it.each(['resolve', 'reject'])('preserves navigation away while an already-dispatched activation later %ss', async (outcome) => {
    const write = deferred(); activateProfile.mockReturnValue(write.promise);
    const { user } = renderPage(); await activate();
    await user.click(screen.getAllByRole('button', { name: 'Back to Revocation Profiles' })[0]);
    await screen.findByRole('heading', { name: 'Revocation inventory' });
    await act(async () => { if (outcome === 'resolve') write.resolve(profile({ status: 'ACTIVE' })); else write.reject(new Error('Obsolete activation failure')); });
    expect(screen.getByRole('heading', { name: 'Revocation inventory' })).toBeInTheDocument();
    expect(screen.queryByText('Obsolete activation failure')).not.toBeInTheDocument();
    expect(getProfile).toHaveBeenCalledTimes(1);
  });
});

describe('Revocation BrowserRouter precommit boundary', () => {
  it.each([NEXT_PATH, PATH + '?review=browser', PATH])('keeps the current browser entry when an old activation resolves during navigation: %s', async (nextPath) => {
    const write = deferred(); const nextRead = deferred();
    activateProfile.mockReturnValue(write.promise); getProfile.mockResolvedValueOnce(profile()).mockReturnValue(nextRead.promise);
    window.history.replaceState({}, '', PATH); renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>); await activate();
    const key = window.history.state?.key;
    await act(async () => { write.resolve(profile({ status: 'ACTIVE', name: 'Obsolete activation' })); queueMicrotask(() => navigateTo(nextPath)); });
    expect(window.history.state?.key).not.toBe(key);
    expect(screen.getByTestId('current-route')).toHaveTextContent(nextPath);
    expect(screen.queryByText('Obsolete activation')).not.toBeInTheDocument();
    expect(getProfile).toHaveBeenCalledTimes(2);
    await act(async () => { nextRead.resolve(profile({ id: nextPath === NEXT_PATH ? NEXT_ID : ID, name: 'Current browser profile' })); });
    await screen.findByRole('heading', { name: 'Current browser profile' });
  });

  it.each([NEXT_PATH, PATH + '?review=browser', PATH])('does not dispatch from the previous entry after history changes but before React commits: %s', async (nextPath) => {
    getProfile.mockImplementation(async (id) => profile({ id }));
    window.history.replaceState({}, '', PATH); renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    const oldButton = await screen.findByRole('button', { name: /^activate$/i });
    await act(async () => { navigateTo(nextPath); fireEvent.click(oldButton); });
    expect(activateProfile).not.toHaveBeenCalled();
    expect(screen.getByTestId('current-route')).toHaveTextContent(nextPath);
  });
});

describe('Revocation detail localized native states', () => {
  it.each(['en', 'de', 'es', 'fr', 'ja', 'nl'])('resolves policy, lifecycle, scope and retry messages in %s without fallback', async (locale) => {
    const messages = JSON.parse(readFileSync(resolve('public', 'locales', locale, 'console.json'), 'utf8'));
    const translations = createInstance();
    await translations.init({ lng: locale, fallbackLng: false, resources: { [locale]: { console: messages } } });
    for (const leaf of ['selectOrganization', 'readDenied', 'profileScopeMismatch', 'activationScopeMismatch', 'retryProfile', 'activate', 'activating', 'activationFailed',
      'statusDraft', 'statusActive', 'statusSuspended', 'statusUnknown', 'checkModes.always', 'checkModes.cached', 'checkModes.offlineGrace', 'checkModes.disabled', 'checkModes.unknown',
      'mechanisms.statusList2021', 'mechanisms.bitstringStatusList', 'mechanisms.tokenStatusList', 'mechanisms.ocsp', 'mechanisms.crl', 'mechanisms.unknown', 'offlineGrace', 'cacheTtl']) {
      const key = 'trust.revocationDetail.' + leaf;
      expect(translations.exists(key, { ns: 'console' })).toBe(true);
      expect(translations.t(key, { ns: 'console' })).not.toBe(key);
    }
  });
});
