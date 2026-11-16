import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import KeyManagementServiceWizard from './KeyManagementServiceWizard';

const { pending, scope, auth, grants, permission, showNotification } = vi.hoisted(() => ({
  pending: { validation: null as Promise<unknown> | null, writes: [] as Promise<unknown>[] },
  scope: { activeOrgId: 'org-1' as string | null },
  auth: { isAuthenticated: true, user: { id: 'principal-1' } },
  grants: new Set<string>(), permission: { isLoading: false }, showNotification: vi.fn(),
}));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showNotification }) }));
// Observe completion only. Serialization, revision headers, installed transport,
// useWizard, all rendered steps and every actual API operation remain real.
vi.mock('../../../services/signingKeysApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/signingKeysApi')>();
  return { ...actual, default: { ...actual.default,
    validateKeyManagementService: (...args: Parameters<typeof actual.validateKeyManagementService>) => {
      pending.validation = actual.validateKeyManagementService(...args);
      return pending.validation;
    },
    updateKeyManagementConfig: (...args: Parameters<typeof actual.updateKeyManagementConfig>) => {
      const result = actual.updateKeyManagementConfig(...args);
      pending.writes.push(result);
      return result;
    },
  } };
});

const NEW_PATH = '/console/org/operator/key-management/services/new';
const CURRENT_PATH = '/console/org/trust';
const REVISION = '"r-11111111-1111-4111-8111-111111111111"';
const NEXT_REVISION = '"r-22222222-2222-4222-8222-222222222222"';
const NAME = 'Continuation fixture signer';
const KEY = 'arn:aws:kms:us-east-2:123456789012:key/fixture-only';
const registry = () => ({ config_revision: REVISION, default_service_id: null,
  services: [], service_type_catalog: [], key_reference_purposes: {}, type_defaults: {}, format_defaults: {},
});
const liveValidation = () => ({ ok: true, basis: 'live', validated_at: '2026-11-09T16:00:00Z',
  checks: [{ name: 'Provider connectivity', status: 'pass', detail: 'Fixture signer is available.', source: 'live' }],
});
let navigateTo: ReturnType<typeof useNavigate>;
function CurrentRoute() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route">{location.pathname}{location.search}{location.hash}</output>;
}
function page() {
  return <BrowserRouter><CurrentRoute /><Routes>
    <Route path={NEW_PATH} element={<KeyManagementServiceWizard />} />
    <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
  </Routes></BrowserRouter>;
}
function installRequests(hold: 'validation' | 'patch' = 'validation') {
  let resolve!: (response: Response) => void;
  const response = new Promise<Response>(done => { resolve = done; });
  let heldResponse: Response;
  const reads: Array<string | null> = [];
  const validations: Array<{ organization: string | null; body: Record<string, unknown> }> = [];
  const writes: Array<{ organization: string | null; body: Record<string, unknown>; revision: string | null; route: string }> = [];
  server.use(
    http.get('*/v1/signing-keys/config', ({ request }) => {
      reads.push(new URL(request.url).searchParams.get('organization_id'));
      return HttpResponse.json(registry());
    }),
    http.post('*/v1/signing-keys/config/validate', async ({ request }) => {
      validations.push({ organization: new URL(request.url).searchParams.get('organization_id'),
        body: await request.json() as Record<string, unknown> });
      const result = HttpResponse.json(liveValidation());
      if (hold === 'validation' && validations.length === 1) { heldResponse = result; return response; }
      return result;
    }),
    http.patch('*/v1/signing-keys/config', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>;
      writes.push({ organization: new URL(request.url).searchParams.get('organization_id'), body,
        revision: request.headers.get('If-Match'), route: window.location.pathname });
      const result = HttpResponse.json({ ...registry(), ...body, config_revision: NEXT_REVISION });
      if (hold === 'patch' && writes.length === 1) { heldResponse = result; return response; }
      return result;
    }),
  );
  const release = (reply?: Response) => resolve(reply || heldResponse);
  return { reads, validations, writes, release, async settle(reply?: Response) {
    await act(async () => {
      release(reply);
      await pending.validation?.catch(() => undefined);
      await Promise.allSettled(pending.writes);
    });
  } };
}
async function reachReview(user: ReturnType<typeof renderWithoutRouter>['user']) {
  await user.click(await screen.findByRole('button', { name: 'AWS KMS key management service' }));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.type(screen.getByRole('textbox', { name: /Service name/i }), NAME);
  await user.type(screen.getByRole('textbox', { name: /Region \/ location/i }), 'us-east-2');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.type(screen.getByRole('textbox', { name: /Key ARN/i }), KEY);
  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
}
beforeEach(() => {
  pending.validation = null; pending.writes.length = 0; showNotification.mockReset();
  scope.activeOrgId = 'org-1'; auth.isAuthenticated = true; auth.user = { id: 'principal-1' };
  permission.isLoading = false; grants.clear(); grants.add('signing-key:view'); grants.add('signing-key:create');
  window.history.replaceState({}, '', NEW_PATH);
});

describe('signing service wizard scope and pending controls', () => {
  const invalidations = [
    ['organization', () => { scope.activeOrgId = 'org-2'; }],
    ['principal', () => { auth.user = { id: 'principal-2' }; }],
    ['authentication', () => { auth.isAuthenticated = false; }],
    ['view grant', () => { grants.delete('signing-key:view'); }],
    ['create grant', () => { grants.delete('signing-key:create'); }],
    ['permission loading', () => { permission.isLoading = true; }],
  ] as const;

  it.each(invalidations)('stops old registration after %s changes during validation', async (_label, invalidate) => {
    const requests = installRequests(); const view = renderWithoutRouter(page());
    await reachReview(view.user);
    await view.user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    invalidate(); view.rerender(page()); await requests.settle();
    expect(requests.writes).toHaveLength(0); expect(showNotification).not.toHaveBeenCalled();
    expect(screen.queryByRole('heading', { name: 'Signing service registered' })).not.toBeInTheDocument();
  });

  it.each([
    ['no organization', () => { scope.activeOrgId = null; }, /Select an organization/],
    ['no view grant', () => { grants.delete('signing-key:view'); }, /permission to view signing services/],
    ['no create grant', () => { grants.delete('signing-key:create'); }, /permission to register signing services/],
    ['unrelated grants', () => { grants.clear(); grants.add('issuer-profile:create'); }, /permission to view signing services/],
    ['signed out', () => { auth.isAuthenticated = false; }, /permission to view signing services/],
  ] as const)('does not load the registry with %s', async (_label, invalidate, message) => {
    const requests = installRequests(); invalidate(); renderWithoutRouter(page());
    expect(screen.getByText(message)).toBeInTheDocument();
    expect(requests.reads).toHaveLength(0); expect(requests.validations).toHaveLength(0); expect(requests.writes).toHaveLength(0);
  });

  it('waits for grants before loading the registry', async () => {
    const requests = installRequests(); permission.isLoading = true;
    const view = renderWithoutRouter(page());
    expect(screen.getByRole('progressbar')).toBeInTheDocument(); expect(requests.reads).toHaveLength(0);
    permission.isLoading = false; view.rerender(page());
    await screen.findByRole('button', { name: 'AWS KMS key management service' });
    expect(requests.reads).toEqual(['org-1']);
  });

  it('locks duplicate submission, validation and Back synchronously while registering', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page()); await reachReview(user);
    const submit = screen.getByRole('button', { name: 'Register service' });
    const validate = screen.getByRole('button', { name: 'Validate connection' });
    const back = screen.getByRole('button', { name: 'Back' });
    act(() => { fireEvent.click(submit); fireEvent.click(validate); fireEvent.click(back); fireEvent.click(submit); });
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
    expect(validate).toBeDisabled(); expect(back).toBeDisabled(); expect(submit).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Copy command' })).toBeDisabled();
    await requests.settle(); expect(requests.writes).toHaveLength(1);
  });

  it('keeps a separate preflight pending without starting registration or navigating', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page()); await reachReview(user);
    const validate = screen.getByRole('button', { name: 'Validate connection' });
    const submit = screen.getByRole('button', { name: 'Register service' });
    const back = screen.getByRole('button', { name: 'Back' });
    act(() => { fireEvent.click(validate); fireEvent.click(submit); fireEvent.click(back); fireEvent.click(validate); });
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
    expect(submit).toBeDisabled(); expect(back).toBeDisabled();
    await requests.settle(); expect(requests.writes).toHaveLength(0);
    expect(submit).toBeEnabled(); expect(screen.getByText('Fixture signer is available.')).toBeInTheDocument();
    await user.click(submit);
    await screen.findByRole('heading', { name: 'Signing service registered' });
    expect(requests.validations).toHaveLength(2); expect(requests.writes).toHaveLength(1);
  });

  it('allows a current validation rejection to be corrected and retried', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page()); await reachReview(user);
    await user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    await requests.settle(HttpResponse.json({ ...liveValidation(), ok: false }));
    await screen.findByText('Key management service validation failed. Review the checks before registering.');
    expect(requests.writes).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Back' }));
    await user.clear(screen.getByRole('textbox', { name: /Key ARN/i }));
    await user.type(screen.getByRole('textbox', { name: /Key ARN/i }), KEY + '-revised');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Register service' }));
    await screen.findByRole('heading', { name: 'Signing service registered' });
    expect(requests.validations).toHaveLength(2);
    expect(requests.writes[0].body.services).toEqual([expect.objectContaining({ key_reference: KEY + '-revised' })]);
    expect(requests.writes[0].revision).toBe(REVISION);
  });

  it.each([false, true])('suppresses an already-dispatched write completion after leaving (error: %s)', async (reject) => {
    const requests = installRequests('patch'); const { user } = renderWithoutRouter(page()); await reachReview(user);
    await user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    await act(async () => { navigateTo(CURRENT_PATH); });
    await requests.settle(reject ? HttpResponse.json({ error: { message: 'Obsolete registry conflict' } }, { status: 412 }) : undefined);
    expect(requests.writes).toHaveLength(1); expect(showNotification).not.toHaveBeenCalled();
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    expect(screen.queryByText(/Obsolete registry conflict/)).not.toBeInTheDocument();
  });

  it('does not carry a completed service or form fields into a new organization', async () => {
    const requests = installRequests(); const view = renderWithoutRouter(page()); await reachReview(view.user);
    await view.user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1)); await requests.settle();
    expect(screen.getByRole('heading', { name: 'Signing service registered' })).toBeInTheDocument();
    scope.activeOrgId = 'org-2'; view.rerender(page());
    await view.user.click(await screen.findByRole('button', { name: 'AWS KMS key management service' }));
    await view.user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('textbox', { name: /Service name/i })).toHaveValue('');
    expect(screen.getByRole('textbox', { name: /Region \/ location/i })).toHaveValue('');
    expect(requests.reads).toEqual(['org-1', 'org-2']);
  });

  it('an old registration finalizer cannot unlock a new organization registration', async () => {
    const requests = installRequests('patch'); const view = renderWithoutRouter(page()); await reachReview(view.user);
    await view.user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.writes).toHaveLength(1)); const oldWrite = pending.writes[0];
    let resolveNew!: (response: Response) => void;
    const newResponse = new Promise<Response>(done => { resolveNew = done; });
    server.use(http.patch('*/v1/signing-keys/config', () => newResponse));
    scope.activeOrgId = 'org-2'; view.rerender(page()); await reachReview(view.user);
    await view.user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(pending.writes).toHaveLength(2));
    await act(async () => { requests.release(); await oldWrite; });
    expect(screen.getByRole('button', { name: 'Saving...' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Validate connection' })).toBeDisabled();
    expect(showNotification).not.toHaveBeenCalled();
    await act(async () => { resolveNew(HttpResponse.json({ ...registry(), config_revision: NEXT_REVISION })); await pending.writes[1]; });
    expect(screen.getByRole('heading', { name: 'Signing service registered' })).toBeInTheDocument();
    expect(showNotification).toHaveBeenCalledTimes(1);
  });

  it.each(['route', 'organization'] as const)('does not retain an obsolete preflight result after changing %s', async (change) => {
    const requests = installRequests(); const view = renderWithoutRouter(page()); await reachReview(view.user);
    await view.user.click(screen.getByRole('button', { name: 'Validate connection' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    if (change === 'route') await act(async () => { navigateTo(CURRENT_PATH); });
    else { scope.activeOrgId = 'org-2'; view.rerender(page()); }
    await requests.settle(change === 'route'
      ? HttpResponse.json({ error: { message: 'Obsolete preflight failure' } }, { status: 403 }) : undefined);
    expect(requests.writes).toHaveLength(0); expect(showNotification).not.toHaveBeenCalled();
    expect(screen.queryByText('Fixture signer is available.')).not.toBeInTheDocument();
    expect(screen.queryByText(/Gateway validation failed/)).not.toBeInTheDocument();
    if (change === 'organization') await screen.findByRole('button', { name: 'AWS KMS key management service' });
  });

  it('releases controls after a current preflight request fails', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page()); await reachReview(user);
    await user.click(screen.getByRole('button', { name: 'Validate connection' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    await requests.settle(HttpResponse.json({ error: { message: 'Fixture preflight failure' } }, { status: 403 }));
    await screen.findByText('Gateway validation failed. Verify connectivity and credentials, then try again.');
    expect(screen.getByRole('button', { name: 'Register service' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Back' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Validate connection' })).toBeEnabled();
    expect(requests.writes).toHaveLength(0);
  });

  it.each([false, true])('keeps clipboard completion feedback within its view (leave: %s)', async (leave) => {
    installRequests(); const { user } = renderWithoutRouter(page()); await reachReview(user);
    let finishCopy!: () => void;
    const copied = new Promise<void>(done => { finishCopy = done; });
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockReturnValue(copied);
    try {
      await user.click(screen.getByRole('button', { name: 'Copy command' }));
      expect(write).toHaveBeenCalledTimes(1);
      if (leave) await act(async () => { navigateTo(CURRENT_PATH); });
      await act(async () => { finishCopy(); await copied; });
      if (leave) expect(showNotification).not.toHaveBeenCalled();
      else expect(showNotification).toHaveBeenCalledWith('Copied to clipboard.', 'success');
    } finally { write.mockRestore(); }
  });

  it.each([NEW_PATH, NEW_PATH + '?entry=next', NEW_PATH + '#next'])('resets the form on a committed new history entry %s', async (destination) => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page()); await reachReview(user);
    await user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    const oldKey = window.history.state?.key;
    await act(async () => { navigateTo(destination); });
    expect(window.history.state?.key).not.toBe(oldKey);
    await user.click(await screen.findByRole('button', { name: 'AWS KMS key management service' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('textbox', { name: /Service name/i })).toHaveValue('');
    await requests.settle(); expect(requests.writes).toHaveLength(0); expect(showNotification).not.toHaveBeenCalled();
  });
});

describe('signing service wizard browser history transition ownership', () => {
  it.each([CURRENT_PATH, NEW_PATH, NEW_PATH + '?entry=next', NEW_PATH + '#next'])('stops validation follow-up before the route transition to %s commits', async (destination) => {
    const requests = installRequests();
    let release!: () => void; let destinationReady = false;
    const transition = new Promise<void>(done => { release = done; });
    const initialKey = window.history.state?.key || 'default';
    function Destination() { if (!destinationReady) throw transition; return <h1>Current Trust overview</h1>; }
    function Entry() { return useLocation().key === initialKey ? <KeyManagementServiceWizard /> : <Destination />; }
    const { user } = renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentRoute /><Routes>
        <Route path={NEW_PATH} element={destination === CURRENT_PATH ? <KeyManagementServiceWizard /> : <Entry />} />
        <Route path={CURRENT_PATH} element={<Destination />} />
      </Routes>
    </Suspense></BrowserRouter>);
    await reachReview(user); await user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    await act(async () => { navigateTo(destination); });
    expect(window.location.pathname + window.location.search + window.location.hash).toBe(destination);
    expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
    await requests.settle();
    expect(requests.writes).toHaveLength(0); expect(showNotification).not.toHaveBeenCalled();
    destinationReady = true; await act(async () => { release(); });
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
  });
});

describe('signing service wizard registration continuation', () => {
  it.each([false, true])('keeps the configuration write within the initiating view (leave before live validation: %s)', async (leave) => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page());
    await reachReview(user);
    await user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    expect(requests.validations[0]).toMatchObject({ organization: 'org-1', body: {
      service_type: 'aws-kms', name: NAME, key_reference: KEY, live_probe: true,
    } });
    if (leave) {
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    }
    await requests.settle();
    expect(requests.writes.map(({ route }) => route), `REQUEST_TRACE=${JSON.stringify(requests.writes)}`)
      .toEqual(leave ? [] : [NEW_PATH]);
    if (leave) {
      expect(showNotification).not.toHaveBeenCalled();
      expect(screen.getByTestId('current-route')).toHaveTextContent(CURRENT_PATH);
    } else {
      expect(requests.writes[0]).toMatchObject({ organization: 'org-1', revision: REVISION });
      expect(requests.writes[0].body).not.toHaveProperty('config_revision');
      expect(screen.getByRole('heading', { name: 'Signing service registered' })).toBeInTheDocument();
      expect(showNotification).toHaveBeenCalledWith('Registered key management service.', 'success');
    }
  });
});

describe('independent audit suspended return navigation', () => {
  it('does not show registration success when an obsolete validation was discarded and the browser returns before destination commit', async () => {
    const requests = installRequests();
    let release!: () => void; let destinationReady = false;
    const transition = new Promise<void>(done => { release = done; });
    function Destination() { if (!destinationReady) throw transition; return <h1>Current Trust overview</h1>; }
    const { user } = renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentRoute /><Routes>
        <Route path={NEW_PATH} element={<KeyManagementServiceWizard />} />
        <Route path={CURRENT_PATH} element={<Destination />} />
      </Routes>
    </Suspense></BrowserRouter>);
    await reachReview(user); await user.click(screen.getByRole('button', { name: 'Register service' }));
    await waitFor(() => expect(requests.validations).toHaveLength(1));
    const originalKey = window.history.state?.key;
    await act(async () => { navigateTo(CURRENT_PATH); });
    expect(window.location.pathname).toBe(CURRENT_PATH);
    expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
    await requests.settle();
    expect(requests.writes).toHaveLength(0);
    await act(async () => { navigateTo(-1); });
    await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
    expect(window.history.state?.key).toBe(originalKey);
    await waitFor(() => expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH));
    expect(requests.writes).toHaveLength(0);
    destinationReady = true; await act(async () => { release(); });
    expect(screen.queryByRole('heading', { name: 'Signing service registered' })).not.toBeInTheDocument();
    await screen.findByRole('heading', { name: 'Register Key Management Service' });
    expect(await screen.findByRole('button', { name: 'AWS KMS key management service' })).toBeEnabled();
    expect(requests.reads).toHaveLength(2);
  });

  it.each([
    ['live validation still pending', 'validation', false, false],
    ['registry write still pending', 'patch', false, false],
    ['registry write completed elsewhere', 'patch', false, true],
    ['preflight completed elsewhere', 'validation', true, true],
  ] as const)('returns to a fresh usable form with %s', async (_label, hold, preflight, settleBeforeReturn) => {
    const requests = installRequests(hold);
    let release!: () => void; let destinationReady = false;
    const transition = new Promise<void>(done => { release = done; });
    function Destination() { if (!destinationReady) throw transition; return <h1>Current Trust overview</h1>; }
    const { user } = renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentRoute /><Routes>
        <Route path={NEW_PATH} element={<KeyManagementServiceWizard />} />
        <Route path={CURRENT_PATH} element={<Destination />} />
      </Routes>
    </Suspense></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByRole('button', { name: preflight ? 'Validate connection' : 'Register service' }));
    await waitFor(() => expect(hold === 'patch' ? requests.writes : requests.validations).toHaveLength(1));
    const originalKey = window.history.state?.key;
    await act(async () => { navigateTo(CURRENT_PATH); });
    expect(window.location.pathname).toBe(CURRENT_PATH);
    expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
    if (settleBeforeReturn) await requests.settle();
    await act(async () => { navigateTo(-1); });
    await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
    expect(window.history.state?.key).toBe(originalKey);
    destinationReady = true; await act(async () => { release(); });
    expect(await screen.findByRole('button', { name: 'AWS KMS key management service' })).toBeEnabled();
    if (!settleBeforeReturn) await requests.settle();
    expect(requests.writes).toHaveLength(hold === 'patch' ? 1 : 0);
    expect(showNotification).not.toHaveBeenCalled();
    expect(screen.queryByRole('heading', { name: 'Signing service registered' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'AWS KMS key management service' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('textbox', { name: /Service name/i })).toHaveValue('');
    expect(screen.getByRole('textbox', { name: /Service name/i })).toBeEnabled();
    expect(requests.reads).toHaveLength(2);
  });
});
