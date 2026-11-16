import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInstance } from 'i18next';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { useLayoutEffect } from 'react';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithRouter, renderWithoutRouter, screen } from '@test/utils';
import TrustProfileDetailPage from '../TrustProfileDetailPage';

const { getProfile, listIssuers, addIssuer, getWalletCompatibility, context, permission, grants } = vi.hoisted(() => ({
  getProfile: vi.fn(),
  listIssuers: vi.fn(),
  addIssuer: vi.fn(),
  context: { activeOrgId: 'org-1' as string | null },
  permission: { isLoading: false },
  grants: new Set<string>(),
  getWalletCompatibility: vi.fn(),
}));

vi.mock('../../../../services/presentationPolicyApi', () => ({
  getTrustProfile: getProfile,
  listTrustProfileIssuers: listIssuers,
  addTrustProfileIssuer: addIssuer,
  getTrustProfileWalletCompatibility: getWalletCompatibility,
}));

vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));

let navigateTo: ReturnType<typeof useNavigate>;
function NavigationDriver() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route">{location.pathname}{location.search}</output>;
}

function page() {
  return <><NavigationDriver /><Routes>
      <Route path="/console/org/trust/profiles/:id" element={<TrustProfileDetailPage />} />
      <Route path="/console/org/templates/credentials" element={<h1>Credential template inventory</h1>} />
      <Route path="/console/org/trust/profiles/:id/edit" element={<h1>Edit profile destination</h1>} />
      <Route path="/elsewhere" element={<h1>Another page</h1>} />
    </Routes></>;
}

function renderPage() {
  return renderWithRouter(page(), { initialEntries: ['/console/org/trust/profiles/profile-1'] });
}

const profile = (overrides = {}) => ({
  id: 'profile-1', organization_id: 'org-1', name: 'Campus trust', status: 'active',
  supported_formats: ['SD_JWT_VC'], trust_sources: [], ...overrides,
});
const issuer = (overrides = {}) => ({
  id: 'link-1', trust_profile_id: 'profile-1', issuer_id: 'entity-1',
  issuer_entity: { id: 'entity-1', organization_id: 'org-1', issuer_id: 'did:web:issuer.example' },
  name: 'Inventory issuer', did: 'did:web:issuer.example', issuer_did: 'did:web:issuer.example',
  relationship_status: 'TRUSTED', compliance_status: 'COMPLIANT', ...overrides,
});
function deferred<T = unknown>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
beforeEach(() => {
  vi.clearAllMocks();
  window.history.replaceState({}, '', '/');
  context.activeOrgId = 'org-1';
  permission.isLoading = false;
  grants.clear();
  for (const grant of ['trust-profile:view', 'trust-profile:create', 'trust-profile:edit', 'trusted-issuer:view', 'trusted-issuer:create']) grants.add(grant);
  getProfile.mockReset().mockResolvedValue(profile());
  listIssuers.mockReset().mockResolvedValue([]);
  addIssuer.mockReset().mockResolvedValue(issuer());
  getWalletCompatibility.mockReset().mockRejectedValue(new Error('Unsupported native route'));
});

afterEach(() => { vi.restoreAllMocks(); });

async function openIssuerDialog(view: Pick<ReturnType<typeof renderPage>, 'user'>) {
  await screen.findByRole('heading', { name: 'Campus trust' });
  await waitFor(() => expect(screen.getByTestId('issuers.addButton')).toBeEnabled());
  await view.user.click(screen.getByTestId('issuers.addButton'));
  await view.user.type(screen.getByTestId('addIssuer.name'), 'Requested issuer');
  await view.user.type(screen.getByTestId('addIssuer.did'), 'did:web:issuer.example');
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
    expect(listIssuers.mock.calls[0].slice(0, 2)).toEqual(['profile-1', 'org-1']);
  });

  it.each(['en', 'de', 'es', 'fr', 'ja', 'nl'])('provides the new guidance and destination label in %s without fallback', async (locale) => {
    const messages = JSON.parse(readFileSync(
      resolve('public', 'locales', locale, 'console.json'), 'utf8',
    ));
    const translations = createInstance();
    await translations.init({ lng: locale, fallbackLng: false, resources: { [locale]: { console: messages } } });
    for (const suffix of [
      'credentialWalletGuidance', 'viewCredentialTemplates', 'selectOrganization', 'profileReadDenied',
      'issuerReadDenied', 'profileScopeMismatch', 'retryProfile', 'retryIssuers', 'issuerScopeMismatch',
      'issuerNotConfirmed', 'issuerLoadFailed', 'issuerAddFailed', 'issuerAwaitingReadback', 'statusUnknown',
      'relationshipStatusLabel', 'issuerComplianceLabel', 'statusDraft', 'statusActive', 'statusSuspended',
      'statusArchived', 'relationshipTrusted', 'relationshipDenied', 'relationshipUnderReview',
      'complianceAccredited', 'complianceCompliant', 'complianceSuspended', 'complianceRevoked',
    ]) {
      const key = `trust.trustProfileDetail.${suffix}`;
      expect(translations.exists(key, { ns: 'console' })).toBe(true);
      expect(translations.t(key, { ns: 'console' })).not.toBe(key);
    }
  });
});

describe('Trust profile current organization and native grants', () => {
  it.each(['organization', 'permissions-loading', 'profile-view'])('does not read or expose actions without current %s', async (missing) => {
    if (missing === 'organization') context.activeOrgId = null;
    if (missing === 'permissions-loading') permission.isLoading = true;
    if (missing === 'profile-view') grants.delete('trust-profile:view');
    renderPage();
    await act(async () => {});
    expect(getProfile).not.toHaveBeenCalled();
    expect(listIssuers).not.toHaveBeenCalled();
    expect(screen.queryByTestId('issuers.addButton')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  });

  it.each([{ id: 'other-profile' }, { organization_id: 'other-org' }, { organization_id: undefined }])('rejects a returned profile outside the route and selected owner: %j', async (wrong) => {
    getProfile.mockResolvedValue(profile(wrong));
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i);
    expect(screen.queryByRole('heading', { name: 'Campus trust' })).not.toBeInTheDocument();
    expect(listIssuers).not.toHaveBeenCalled();
  });

  it.each(['organization', 'profile', 'query', 'entry'])('discards late profile responses after a %s change', async (change) => {
    const old = deferred();
    getProfile.mockReturnValueOnce(old.promise).mockResolvedValueOnce(profile({
      id: change === 'profile' ? 'profile-2' : 'profile-1',
      organization_id: change === 'organization' ? 'org-2' : 'org-1', name: 'Current profile',
    }));
    const view = renderPage();
    await waitFor(() => expect(getProfile).toHaveBeenCalledTimes(1));
    if (change === 'organization') { context.activeOrgId = 'org-2'; view.rerender(page()); }
    else await act(async () => { await navigateTo(change === 'profile' ? '/console/org/trust/profiles/profile-2'
      : '/console/org/trust/profiles/profile-1' + (change === 'query' ? '?review=next' : '')); });
    await screen.findByRole('heading', { name: 'Current profile' });
    await act(async () => { old.resolve(profile({ name: 'Obsolete profile' })); });
    expect(screen.queryByText('Obsolete profile')).not.toBeInTheDocument();
    expect(listIssuers.mock.calls.every(([id, org]) => id === (change === 'profile' ? 'profile-2' : 'profile-1')
      && org === (change === 'organization' ? 'org-2' : 'org-1'))).toBe(true);
  });

  it.each(['trust-profile:create', 'trusted-issuer:create', 'trusted-issuer:view'])('withholds issuer add without the native %s grant', async (grant) => {
    grants.delete(grant);
    renderPage();
    await screen.findByRole('heading', { name: 'Campus trust' });
    expect(screen.queryByTestId('issuers.addButton')).not.toBeInTheDocument();
    if (grant === 'trusted-issuer:view') expect(listIssuers).not.toHaveBeenCalled();
  });

  it('uses the edit grant separately from both native issuer-create grants', async () => {
    grants.delete('trust-profile:edit');
    const view = renderPage();
    await screen.findByRole('heading', { name: 'Campus trust' });
    await waitFor(() => expect(screen.getByTestId('issuers.addButton')).toBeEnabled());
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    grants.add('trust-profile:edit');
    grants.delete('trust-profile:create');
    view.rerender(page());
    await view.user.click(await screen.findByRole('button', { name: 'Edit' }));
    expect(await screen.findByRole('heading', { name: 'Edit profile destination' })).toBeInTheDocument();
    expect(addIssuer).not.toHaveBeenCalled();
  });

  it('withdraws a pending profile read when current account permissions are being reloaded', async () => {
    const old = deferred();
    getProfile.mockReturnValueOnce(old.promise);
    const view = renderPage();
    await waitFor(() => expect(getProfile).toHaveBeenCalledTimes(1));
    permission.isLoading = true;
    view.rerender(page());
    await act(async () => { old.resolve(profile()); });
    expect(screen.queryByRole('heading', { name: 'Campus trust' })).not.toBeInTheDocument();
    expect(listIssuers).not.toHaveBeenCalled();
  });

  it('renders unknown relationship and compliance states explicitly', async () => {
    listIssuers.mockResolvedValue([issuer({ relationship_status: undefined, compliance_status: undefined })]);
    renderPage();
    await screen.findByText('Inventory issuer');
    expect(screen.getAllByText('Unknown')).toHaveLength(2);
    expect(screen.getByText('Trust relationship')).toBeInTheDocument();
    expect(screen.getByText('Issuer compliance')).toBeInTheDocument();
  });

  it('preserves profile loading errors and supports an explicit read retry', async () => {
    getProfile.mockRejectedValueOnce(new Error('Profile dependency unavailable')).mockResolvedValueOnce(profile());
    const view = renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Profile dependency unavailable');
    await view.user.click(screen.getByRole('button', { name: 'Retry profile' }));
    await screen.findByRole('heading', { name: 'Campus trust' });
    expect(getProfile).toHaveBeenCalledTimes(2);
  });

  it('preserves issuer inventory errors and retries without claiming an empty list', async () => {
    listIssuers.mockRejectedValueOnce(new Error('Issuer inventory unavailable')).mockResolvedValueOnce([issuer()]);
    const view = renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Issuer inventory unavailable');
    expect(screen.queryByText('No trusted issuers configured for this profile.')).not.toBeInTheDocument();
    await view.user.click(screen.getByRole('button', { name: 'Retry issuer list' }));
    expect(await screen.findByText('Inventory issuer')).toBeInTheDocument();
    expect(addIssuer).not.toHaveBeenCalled();
  });

  it('keeps relationship trust distinct from issuer compliance and does not manufacture Active', async () => {
    getProfile.mockResolvedValue(profile({ status: undefined }));
    listIssuers.mockResolvedValue([issuer({ relationship_status: 'DENIED', compliance_status: 'COMPLIANT', status: 'COMPLIANT' })]);
    renderPage();
    await screen.findByText('Inventory issuer');
    expect(screen.getByText('Trust relationship')).toBeInTheDocument();
    expect(screen.getByText('Issuer compliance')).toBeInTheDocument();
    expect(screen.getByText('Denied')).toBeInTheDocument();
    expect(screen.getByText('Compliant')).toBeInTheDocument();
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
  });
});

describe('Trust profile issuer action lifetime', () => {
  it('locks synchronous duplicate submits and keeps the dialog open through real inventory confirmation', async () => {
    const write = deferred();
    const readback = deferred();
    addIssuer.mockReturnValueOnce(write.promise);
    listIssuers.mockResolvedValueOnce([]).mockReturnValueOnce(readback.promise);
    const view = renderPage();
    await openIssuerDialog(view);
    const submit = screen.getByTestId('addIssuer.submit');
    act(() => { fireEvent.click(submit); fireEvent.click(submit); });
    expect(addIssuer).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('addIssuer.name')).toBeDisabled();
    await view.user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    const backdrop = document.querySelector('.MuiBackdrop-root');
    if (backdrop) fireEvent.click(backdrop);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await act(async () => { write.resolve(issuer({ name: 'Unconfirmed write response' })); });
    await waitFor(() => expect(listIssuers).toHaveBeenCalledTimes(2));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.queryByText('Unconfirmed write response')).not.toBeInTheDocument();
    await act(async () => { readback.resolve([issuer({ name: 'Confirmed inventory issuer' })]); });
    expect(await screen.findByText('Confirmed inventory issuer')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('retries a current rejected add without losing form inputs', async () => {
    addIssuer.mockRejectedValueOnce(new Error('Issuer service rejected the request')).mockResolvedValueOnce(issuer());
    listIssuers.mockResolvedValueOnce([]).mockResolvedValueOnce([issuer()]);
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Issuer service rejected the request');
    expect(screen.getByTestId('addIssuer.name')).toHaveValue('Requested issuer');
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(addIssuer).toHaveBeenCalledTimes(2);
  });

  it('retries inventory confirmation without repeating an acknowledged link write', async () => {
    listIssuers.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('Readback unavailable')).mockResolvedValueOnce([issuer()]);
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Readback unavailable');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await view.user.click(screen.getByRole('button', { name: 'Retry issuer list' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(addIssuer).toHaveBeenCalledTimes(1);
    expect(listIssuers).toHaveBeenCalledTimes(3);
  });

  it('keeps an acknowledged relationship pending when the actual list does not contain it', async () => {
    listIssuers.mockResolvedValueOnce([]).mockResolvedValueOnce([]).mockResolvedValueOnce([issuer()]);
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be confirmed in the current list');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await view.user.click(screen.getByRole('button', { name: 'Retry issuer list' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(addIssuer).toHaveBeenCalledTimes(1);
  });

  it.each([
    { trust_profile_id: 'other-profile' },
    { issuer_id: 'other-entity' },
    { issuer_entity: { id: 'entity-1', organization_id: 'other-org', issuer_id: 'did:web:issuer.example' } },
    { did: 'did:web:other.example' },
    { id: undefined },
  ])('does not close or display a mutation response with mismatched scope: %j', async (wrong) => {
    addIssuer.mockResolvedValueOnce(issuer(wrong));
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    expect(await screen.findByRole('alert')).toHaveTextContent(/issuer.*match|issuer.*scope/i);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(listIssuers).toHaveBeenCalledTimes(1);
  });

  it.each(['organization', 'grant', 'query', 'entry'])('invalidates pending actions on %s changes and ignores their later errors', async (change) => {
    const old = deferred();
    addIssuer.mockReturnValueOnce(old.promise);
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    if (change === 'organization') {
      context.activeOrgId = 'org-2'; getProfile.mockResolvedValue(profile({ organization_id: 'org-2' })); view.rerender(page());
    } else if (change === 'grant') {
      grants.delete('trusted-issuer:create'); view.rerender(page());
    } else await act(async () => { await navigateTo('/console/org/trust/profiles/profile-1' + (change === 'query' ? '?review=next' : '')); });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await screen.findByRole('heading', { name: 'Campus trust' });
    await act(async () => { old.reject(new Error('Obsolete issuer failure')); });
    expect(screen.queryByText('Obsolete issuer failure')).not.toBeInTheDocument();
    expect(screen.queryByText('Inventory issuer')).not.toBeInTheDocument();
  });

  it('does not let an old successful action close a new dialog on a new route entry', async () => {
    const old = deferred();
    addIssuer.mockReturnValueOnce(old.promise);
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    await act(async () => { await navigateTo('/console/org/trust/profiles/profile-1?review=next'); });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await openIssuerDialog(view);
    await act(async () => { old.resolve(issuer({ name: 'Obsolete issuer' })); });
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByTestId('addIssuer.name')).toHaveValue('Requested issuer');
    expect(screen.queryByText('Obsolete issuer')).not.toBeInTheDocument();
  });

  it('uses the real service action boundary to stop writes after a delayed inventory outlives its route', async () => {
    const actual = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>('../../../../services/presentationPolicyApi');
    getProfile.mockImplementation(actual.getTrustProfile);
    listIssuers.mockImplementation(actual.listTrustProfileIssuers);
    addIssuer.mockImplementation(actual.addTrustProfileIssuer);
    const inventory = deferred();
    let reads = 0; let entityPosts = 0; let linkPosts = 0;
    server.use(
      http.get('*/v1/trust-profiles/profile-1', () => HttpResponse.json(profile())),
      http.get('*/v1/trust-profiles/profile-1/issuers', () => HttpResponse.json([])),
      http.get('*/v1/issuer-entities', async () => {
        reads++;
        if (reads === 2) await inventory.promise;
        return HttpResponse.json([]);
      }),
      http.post('*/v1/issuer-entities', () => { entityPosts++; return HttpResponse.json(issuer().issuer_entity); }),
      http.post('*/v1/trust-profiles/profile-1/issuers', () => { linkPosts++; return HttpResponse.json(issuer()); }),
    );
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    await waitFor(() => expect(reads).toBe(2));
    await act(async () => { await navigateTo('/elsewhere'); });
    await screen.findByRole('heading', { name: 'Another page' });
    await act(async () => {
      inventory.resolve(undefined);
      await addIssuer.mock.results[0].value.catch(() => {});
    });
    expect(entityPosts).toBe(0);
    expect(linkPosts).toBe(0);
  });
});

describe('Trust profile browser entry before React transition commit', () => {
  it.each([
    '/console/org/trust/profiles/profile-2',
    '/console/org/trust/profiles/profile-1?review=browser',
    '/console/org/trust/profiles/profile-1',
  ])('does not start obsolete readback after a browser entry changes: %s', async (nextPath) => {
    const write = deferred();
    const nextProfile = deferred();
    getProfile.mockResolvedValueOnce(profile()).mockReturnValue(nextProfile.promise);
    addIssuer.mockReturnValueOnce(write.promise);
    window.history.replaceState({}, '', '/console/org/trust/profiles/profile-1');
    const view = renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    const oldKey = window.history.state?.key;
    await act(async () => {
      write.resolve(issuer());
      queueMicrotask(() => navigateTo(nextPath));
    });
    expect(window.history.state?.key).not.toBe(oldKey);
    expect(screen.getByTestId('current-route')).toHaveTextContent(nextPath);
    expect(listIssuers).toHaveBeenCalledTimes(1);
    await act(async () => { nextProfile.resolve(profile({ id: nextPath.includes('profile-2') ? 'profile-2' : 'profile-1', name: 'Current profile' })); });
    await screen.findByRole('heading', { name: 'Current profile' });
  });

  it('does not dispatch from the old browser dialog before navigation commits', async () => {
    getProfile.mockImplementation(async (id) => profile({ id }));
    window.history.replaceState({}, '', '/console/org/trust/profiles/profile-1');
    const view = renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    await openIssuerDialog(view);
    const oldSubmit = screen.getByTestId('addIssuer.submit');
    await act(async () => {
      navigateTo('/console/org/trust/profiles/profile-2');
      fireEvent.click(oldSubmit);
    });
    expect(addIssuer).not.toHaveBeenCalled();
    expect(screen.getByTestId('current-route')).toHaveTextContent('/profile-2');
  });

  it.each(['inventory', 'entity'])('does not launch a later real-service write when browser navigation overtakes the %s continuation', async (stage) => {
    const actual = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>('../../../../services/presentationPolicyApi');
    const transport = await import('../../../../services/api');
    const delayed = deferred<any>();
    const nativeEntity = { ...issuer().issuer_entity, display_name: 'Native issuer', compliance_status: 'COMPLIANT' };
    let inventoryCalls = 0; let entityPosts = 0; let linkPosts = 0;
    vi.spyOn(transport, 'get').mockImplementation(async () => {
      inventoryCalls++;
      return stage === 'inventory' ? delayed.promise : [];
    });
    vi.spyOn(transport, 'post').mockImplementation(async (endpoint) => {
      if (endpoint === '/v1/issuer-entities') {
        entityPosts++;
        return stage === 'entity' ? delayed.promise : nativeEntity;
      }
      linkPosts++;
      return issuer();
    });
    addIssuer.mockImplementation(actual.addTrustProfileIssuer);
    getProfile.mockImplementation(async (id) => profile({ id }));
    window.history.replaceState({}, '', '/console/org/trust/profiles/profile-1');
    const view = renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    await waitFor(() => expect(stage === 'inventory' ? inventoryCalls : entityPosts).toBe(1));
    await act(async () => {
      delayed.resolve(stage === 'inventory' ? [] : nativeEntity);
      queueMicrotask(() => navigateTo('/console/org/trust/profiles/profile-2'));
      await addIssuer.mock.results[0].value.catch(() => {});
    });
    expect(entityPosts).toBe(stage === 'inventory' ? 0 : 1);
    expect(linkPosts).toBe(0);
    expect(screen.getByTestId('current-route')).toHaveTextContent('/profile-2');
  });

  it('preserves a readback failure after closing the dialog and retries only the inventory', async () => {
    listIssuers.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('Accepted link inventory unavailable')).mockResolvedValueOnce([issuer()]);
    const view = renderPage();
    await openIssuerDialog(view);
    await view.user.click(screen.getByTestId('addIssuer.submit'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Accepted link inventory unavailable');
    await view.user.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('alert')).toHaveTextContent('Accepted link inventory unavailable');
    await view.user.click(screen.getByRole('button', { name: 'Retry issuer list' }));
    expect(await screen.findByText('Inventory issuer')).toBeInTheDocument();
    expect(addIssuer).toHaveBeenCalledTimes(1);
  });
});
