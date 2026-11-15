import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useLayoutEffect } from 'react';
import { BrowserRouter, Link, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithRouter, renderWithoutRouter, screen } from '@test/utils';
import RevocationProfileWizard from '../RevocationProfileWizard';

const { createProfile, context, permission, grants } = vi.hoisted(() => ({
  createProfile: vi.fn(), context: { activeOrgId: 'org-1' as string | null },
  permission: { isLoading: false }, grants: new Set<string>(),
}));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  createRevocationProfile: createProfile,
}));
vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => context,
}));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));

const CREATED_ID = '11111111-1111-4111-8111-111111111111';
const NEW_PATH = '/console/org/trust/revocation/new';
const CURRENT_PATH = '/console/org/trust';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

// Exact public create ProfileResponse: native creation returns DRAFT, not ACTIVE.
const createdProfile = (overrides: Record<string, unknown> = {}) => ({
  id: CREATED_ID, organization_id: 'org-1', name: 'New revocation profile', status: 'DRAFT',
  check_mode: 'ALWAYS', revocation_mechanism: ['STATUS_LIST_2021'], mechanism_priority: ['STATUS_LIST_2021'],
  issuer_config: { auto_allocate_index: true, batch_update_interval_seconds: 600, list_size: 131072 },
  status_list_url: 'https://status.example.test/v1/organizations/org-1/revocation-profiles/' + CREATED_ID + '/status-lists/{mechanism}/{purpose}',
  created_at: '2026-11-09T12:00:00+00:00', updated_at: '2026-11-09T12:00:00+00:00',
  ...overrides,
});

let navigateTo: ReturnType<typeof useNavigate>;
function CurrentRoute() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route" data-entry-key={location.key}>{location.pathname}{location.search}{location.hash}</output>;
}

function page() {
  return <><CurrentRoute /><Routes>
    <Route path={NEW_PATH} element={<RevocationProfileWizard />} />
    <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
    <Route path="/console/org/trust/revocation/:id" element={<h1>Created profile detail</h1>} />
  </Routes></>;
}

function renderPage() { return renderWithRouter(page(), { initialEntries: [NEW_PATH] }); }
function fillName(name = 'New revocation profile') {
  fireEvent.change(screen.getByTestId('revocationWizard.name'), { target: { value: name } });
}
function submit() { fireEvent.click(screen.getByTestId('revocationWizard.submit')); }
async function settleSubmission() {
  await act(async () => { await createProfile.mock.results[0].value.catch(() => undefined); });
}

beforeEach(() => {
  createProfile.mockReset().mockResolvedValue(createdProfile());
  context.activeOrgId = 'org-1'; permission.isLoading = false;
  grants.clear(); grants.add('revocation-profile:create');
  window.history.replaceState({}, '', NEW_PATH);
});

describe('Revocation Profile creation lifetime', () => {
  it('does not replace the current route when a create response arrives after leaving the wizard', async () => {
    const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>(
      '../../../../services/presentationPolicyApi',
    );
    createProfile.mockImplementation(api.createRevocationProfile);
    const reply = deferred<Record<string, unknown>>();
    const requests: Record<string, unknown>[] = [];
    server.use(http.post('*/v1/revocation-profiles', async ({ request }) => {
      requests.push(await request.json() as Record<string, unknown>);
      return HttpResponse.json(await reply.promise);
    }));

    const { user } = renderWithoutRouter(<BrowserRouter>
      <CurrentRoute />
      <Link to={CURRENT_PATH}>Open Trust overview</Link>
      <Routes>
        <Route path={NEW_PATH} element={<RevocationProfileWizard />} />
        <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
        <Route path="/console/org/trust/revocation/:id" element={<h1>Created profile detail</h1>} />
      </Routes>
    </BrowserRouter>);

    fireEvent.change(screen.getByTestId('revocationWizard.name'), {
      target: { value: 'Deferred revocation profile' },
    });
    await user.click(screen.getByRole('button', { name: 'Create Profile' }));
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0]).toMatchObject({
      organization_id: 'org-1', name: 'Deferred revocation profile',
      check_mode: 'ALWAYS', revocation_mechanism: ['STATUS_LIST_2021'],
    });

    await user.click(screen.getByRole('link', { name: 'Open Trust overview' }));
    expect(await screen.findByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    expect(screen.queryByTestId('revocationWizard.name')).not.toBeInTheDocument();

    // Native create_profile returns the complete DRAFT ProfileResponse. The
    // successful write may exist, but its obsolete page must not own navigation.
    await act(async () => {
      reply.resolve({
        id: CREATED_ID, organization_id: 'org-1', name: 'Deferred revocation profile',
        status: 'DRAFT', check_mode: 'ALWAYS',
        revocation_mechanism: ['STATUS_LIST_2021'], mechanism_priority: ['STATUS_LIST_2021'],
        issuer_config: { auto_allocate_index: true, batch_update_interval_seconds: 600, list_size: 131072 },
        status_list_url: '/v1/organizations/org-1/revocation-profiles/' + CREATED_ID + '/status-lists/{mechanism}/{purpose}',
        created_at: '2026-11-09T12:00:00+00:00', updated_at: '2026-11-09T12:00:00+00:00',
      });
      await expect(createProfile.mock.results[0].value).rejects.toMatchObject({ name: 'AbortError' });
    });

    // The real fetch/JSON adapter and Router have settled before checking
    // that the user's newer route has retained ownership.
    expect(screen.getByTestId('current-route').textContent).toBe(CURRENT_PATH);
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Created profile detail' })).not.toBeInTheDocument();
    expect(requests).toHaveLength(1);
  });
});

describe('Revocation creation organization and native create permission', () => {
  it.each(['no organization', 'empty organization', 'loading permissions', 'view only', 'edit only'])(
    'does not expose or dispatch creation with %s', async (condition) => {
      if (condition === 'no organization') context.activeOrgId = null;
      if (condition === 'empty organization') context.activeOrgId = '';
      if (condition === 'loading permissions') permission.isLoading = true;
      if (condition.endsWith('only')) {
        grants.clear(); grants.add('revocation-profile:' + condition.split(' ')[0]);
      }
      renderPage();
      await act(async () => {});
      expect(screen.queryByTestId('revocationWizard.name')).not.toBeInTheDocument();
      expect(screen.queryByTestId('revocationWizard.submit')).not.toBeInTheDocument();
      expect(createProfile).not.toHaveBeenCalled();
      if (condition === 'loading permissions') expect(screen.getByRole('progressbar')).toBeInTheDocument();
      else expect(screen.getByRole('alert')).toHaveTextContent(/organization|permission/i);
    },
  );

  it('admits the native create grant independently of view and edit, then uses the exact DRAFT response', async () => {
    const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>(
      '../../../../services/presentationPolicyApi',
    );
    createProfile.mockImplementation(api.createRevocationProfile);
    const requests: Record<string, unknown>[] = [];
    server.use(http.post('*/v1/revocation-profiles', async ({ request }) => {
      requests.push(await request.json() as Record<string, unknown>);
      return HttpResponse.json(createdProfile());
    }));
    renderPage(); fillName(); submit();
    await settleSubmission();
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ organization_id: 'org-1', name: 'New revocation profile' });
    expect(screen.getByTestId('current-route').textContent).toBe('/console/org/trust/revocation/' + CREATED_ID);
    expect(screen.getByRole('heading', { name: 'Created profile detail' })).toBeInTheDocument();
  });

  it.each(['organization', 'query', 'hash', 'entry', 'route'])(
    'discards unfinished fields after a committed %s change', async (change) => {
      const view = renderPage(); fillName('Old unfinished draft');
      if (change === 'organization') { context.activeOrgId = 'org-2'; view.rerender(page()); }
      else if (change === 'route') {
        await act(async () => { await navigateTo(CURRENT_PATH); });
        await act(async () => { await navigateTo(NEW_PATH); });
      } else {
        await act(async () => { await navigateTo(NEW_PATH + (change === 'query' ? '?review=new' : change === 'hash' ? '#new' : '')); });
      }
      expect(screen.getByTestId('revocationWizard.name')).toHaveValue('');
      expect(screen.getByTestId('revocationWizard.submit')).toBeDisabled();
      expect(createProfile).not.toHaveBeenCalled();
    },
  );

  it.each(['create grant', 'permission reload'])(
    'withdraws the form and starts a fresh draft when %s returns', async (change) => {
      const view = renderPage(); fillName('Old permission draft');
      if (change === 'create grant') grants.delete('revocation-profile:create');
      else permission.isLoading = true;
      view.rerender(page());
      expect(screen.queryByTestId('revocationWizard.name')).not.toBeInTheDocument();
      grants.add('revocation-profile:create'); permission.isLoading = false;
      view.rerender(page());
      expect(screen.getByTestId('revocationWizard.name')).toHaveValue('');
      expect(screen.getByTestId('revocationWizard.submit')).toBeDisabled();
      expect(createProfile).not.toHaveBeenCalled();
    },
  );
});

describe('Revocation creation request ownership and acknowledgement', () => {
  it.each(['ALWAYS', 'CACHED', 'OFFLINE_GRACE'])(
    'freezes every editable control during a current %s request and restores editing on failure', async (mode) => {
      const reply = deferred<unknown>(); createProfile.mockReturnValue(reply.promise);
      const { user } = renderPage(); fillName('Submitted profile');
      const name = screen.getByTestId('revocationWizard.name');
      const description = screen.getByTestId('revocationWizard.description');
      const statusUrl = screen.getByTestId('revocationWizard.statusListUrl');
      const checkMode = screen.getByRole('combobox', { name: /revocation check mode/i });
      fireEvent.change(description, { target: { value: 'Submitted description' } });
      fireEvent.change(statusUrl, { target: { value: 'https://status.example.test/current' } });
      if (mode !== 'ALWAYS') {
        fireEvent.mouseDown(checkMode);
        fireEvent.click(screen.getByRole('option', { name: mode === 'CACHED' ? /^cached/i : /^offline grace/i }));
      }
      const inputs = [name, description, statusUrl];
      if (mode !== 'ALWAYS') {
        const timing = screen.getByTestId(mode === 'CACHED' ? 'revocationWizard.cacheTtl' : 'revocationWizard.gracePeriod');
        fireEvent.change(timing, { target: { value: '60' } });
        inputs.push(timing);
      }
      const ocsp = screen.getByRole('checkbox', { name: /^ocsp$/i });
      await user.click(ocsp); submit();
      expect(createProfile).toHaveBeenCalledTimes(1);
      expect(createProfile.mock.calls[0][0]).toMatchObject({
        name: 'Submitted profile', description: 'Submitted description', check_mode: mode,
        status_list_url: 'https://status.example.test/current', revocation_mechanism: ['STATUS_LIST_2021', 'OCSP'],
      });
      try {
        for (const input of inputs) expect(input).toBeDisabled();
        expect(checkMode).toHaveAttribute('aria-disabled', 'true');
        for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled();
        await user.type(name, ' changed while pending');
        expect(name).toHaveValue('Submitted profile'); expect(ocsp).toBeChecked();
      } finally {
        await act(async () => {
          reply.reject(new Error('Current request rejected'));
          await createProfile.mock.results[0].value.catch(() => undefined);
        });
      }
      expect(screen.getByRole('alert')).toHaveTextContent('Current request rejected');
      for (const input of inputs) expect(input).toBeEnabled();
      expect(checkMode).not.toHaveAttribute('aria-disabled', 'true');
      for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeEnabled();
      await user.type(name, ' revised');
      expect(name).toHaveValue('Submitted profile revised');
      expect(createProfile).toHaveBeenCalledTimes(1);
    },
  );

  it('locks duplicate submissions synchronously while the original POST is pending', async () => {
    const reply = deferred<unknown>(); createProfile.mockReturnValue(reply.promise);
    renderPage(); fillName();
    const button = screen.getByTestId('revocationWizard.submit');
    act(() => { fireEvent.click(button); fireEvent.click(button); });
    expect(createProfile).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('revocationWizard.submit')).toBeDisabled();
    await act(async () => { reply.resolve(createdProfile()); await createProfile.mock.results[0].value; });
    expect(screen.getByRole('heading', { name: 'Created profile detail' })).toBeInTheDocument();
  });

  it('retains a current failure and form values, then allows one successful retry', async () => {
    createProfile.mockRejectedValueOnce(new Error('Current create failure')).mockResolvedValueOnce(createdProfile());
    renderPage(); fillName(); submit(); await settleSubmission();
    expect(screen.getByRole('alert')).toHaveTextContent('Current create failure');
    expect(screen.getByTestId('revocationWizard.name')).toHaveValue('New revocation profile');
    expect(screen.getByTestId('revocationWizard.submit')).toBeEnabled();
    submit();
    await act(async () => { await createProfile.mock.results[1].value; });
    expect(createProfile).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('heading', { name: 'Created profile detail' })).toBeInTheDocument();
  });

  it.each([
    ['missing ID', createdProfile({ id: undefined })],
    ['empty ID', createdProfile({ id: '' })],
    ['blank ID', createdProfile({ id: '   ' })],
    ['non-string ID', createdProfile({ id: 27 })],
    ['foreign organization', createdProfile({ organization_id: 'org-2' })],
    ['missing organization', createdProfile({ organization_id: undefined })],
    ['active profile', createdProfile({ status: 'ACTIVE' })],
    ['missing status', createdProfile({ status: undefined })],
    ['missing postimage', null],
  ])('retains the form and reports an unconfirmed creation for %s', async (_label, postimage) => {
    createProfile.mockResolvedValue(postimage);
    renderPage(); fillName(); submit(); await settleSubmission();
    expect(screen.getByRole('alert')).toHaveTextContent(/does not confirm a new draft profile.*selected organization/i);
    expect(screen.getByTestId('revocationWizard.name')).toHaveValue('New revocation profile');
    expect(screen.getByTestId('current-route').textContent).toBe(NEW_PATH);
    expect(screen.queryByRole('heading', { name: 'Created profile detail' })).not.toBeInTheDocument();
    expect(createProfile).toHaveBeenCalledTimes(1);
  });

  it.each(['organization', 'query', 'hash', 'entry', 'route', 'create grant', 'permission reload'].flatMap(
    (change) => ['success', 'error'].map((outcome) => [change, outcome]),
  ))('ignores an old %s request completion with %s after ownership changes', async (change, outcome) => {
    const reply = deferred<unknown>(); createProfile.mockReturnValueOnce(reply.promise);
    const view = renderPage(); fillName('Old submitted draft'); submit();
    expect(createProfile).toHaveBeenCalledTimes(1);
    let expectedPath = NEW_PATH;
    if (change === 'organization') { context.activeOrgId = 'org-2'; view.rerender(page()); }
    else if (change === 'create grant') { grants.delete('revocation-profile:create'); view.rerender(page()); }
    else if (change === 'permission reload') { permission.isLoading = true; view.rerender(page()); }
    else {
      expectedPath = change === 'route' ? CURRENT_PATH : NEW_PATH + (change === 'query' ? '?review=current' : change === 'hash' ? '#current' : '');
      await act(async () => { await navigateTo(expectedPath); });
    }
    await act(async () => {
      if (outcome === 'success') reply.resolve(createdProfile());
      else reply.reject(new Error('Obsolete create failure'));
      await createProfile.mock.results[0].value.catch(() => undefined);
    });
    expect(screen.getByTestId('current-route').textContent).toBe(expectedPath);
    expect(screen.queryByText('Obsolete create failure')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Created profile detail' })).not.toBeInTheDocument();
    if (change === 'route') expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    else if (change === 'create grant' || change === 'permission reload') {
      expect(screen.queryByTestId('revocationWizard.name')).not.toBeInTheDocument();
    } else {
      expect(screen.getByTestId('revocationWizard.name')).toHaveValue('');
      expect(screen.getByTestId('revocationWizard.submit')).toBeDisabled();
    }
    expect(createProfile).toHaveBeenCalledTimes(1);
  });
});

describe('Revocation creation actual BrowserRouter precommit boundary', () => {
  it.each([CURRENT_PATH, NEW_PATH + '?review=browser', NEW_PATH + '#browser', NEW_PATH])(
    'does not dispatch from an old entry after browser history changes but before React commits: %s', async (nextPath) => {
      renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>); fillName();
      const button = screen.getByTestId('revocationWizard.submit');
      const routerKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
      const browserKey = window.history.state?.key;
      await act(async () => {
        navigateTo(nextPath);
        expect(window.history.state?.key).not.toBe(browserKey);
        expect(screen.getByTestId('current-route').getAttribute('data-entry-key')).toBe(routerKey);
        fireEvent.click(button);
      });
      expect(createProfile).not.toHaveBeenCalled();
      expect(screen.getByTestId('current-route').textContent).toBe(nextPath);
    },
  );

  it.each([CURRENT_PATH, NEW_PATH + '?review=browser', NEW_PATH + '#browser', NEW_PATH].flatMap(
    (nextPath) => ['success', 'error'].map((outcome) => [nextPath, outcome]),
  ))('keeps the newer browser entry %s when an old %s settles before React commits', async (nextPath, outcome) => {
    const reply = deferred<unknown>();
    // The asynchronous adapter adds the same promise boundary as an HTTP call,
    // so history can change after its result but before the page continuation.
    createProfile.mockImplementation(async () => await reply.promise);
    renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>); fillName(); submit();
    const routerKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
    const browserKey = window.history.state?.key;
    let observedPrecommitGap = false;
    await act(async () => {
      if (outcome === 'success') reply.resolve(createdProfile());
      else reply.reject(new Error('Obsolete browser create failure'));
      queueMicrotask(() => {
        navigateTo(nextPath);
        observedPrecommitGap = window.history.state?.key !== browserKey
          && screen.getByTestId('current-route').getAttribute('data-entry-key') === routerKey;
      });
      await createProfile.mock.results[0].value.catch(() => undefined);
    });
    expect(observedPrecommitGap).toBe(true);
    expect(screen.getByTestId('current-route').textContent).toBe(nextPath);
    expect(screen.queryByText('Obsolete browser create failure')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Created profile detail' })).not.toBeInTheDocument();
    if (nextPath === CURRENT_PATH) expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    else expect(screen.getByTestId('revocationWizard.name')).toHaveValue('');
    expect(createProfile).toHaveBeenCalledTimes(1);
  });
});
