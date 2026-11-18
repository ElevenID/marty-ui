import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes, useLocation } from 'react-router';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { AuthProvider } from '../../contexts/AuthContext';
import { ConsoleContext } from '../../contexts/ConsoleContext';
import { useAuth } from '../../hooks/useAuth';
import { getCurrentUser, initiateLogin } from '../../services/authApi';
import LoginPage from '../LoginPage';
import ProtectedRoute, { ApplicantConsoleRoute, OrgConsoleRoute } from '../ProtectedRoute';

vi.mock('../../services/authApi', () => ({
  getCurrentUser: vi.fn(),
  initiateLogin: vi.fn(),
  initiateRegister: vi.fn(),
  initiateLogout: vi.fn(),
}));
vi.mock('../../services/organizationsApi', () => ({ getMyOrganizations: vi.fn().mockResolvedValue([]) }));
vi.mock('../../application/routing/appHandoff', () => ({
  shouldBrowserRedirect: () => false,
  redirectBrowser: vi.fn(),
}));

const principal = { user_id: 'confirmed-user', roles: [], capabilities: { 'org:issue': true }, organizations: [] };
const authenticated = { authenticated: true, user: principal };
const anonymous = { authenticated: false, user: null };
const unavailable = (code = 'AUTH_UNAVAILABLE') => Object.assign(new Error('private upstream details'), { code });

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function SessionProbe() {
  const auth = useAuth();
  const location = useLocation();
  return <>
    <output data-testid="auth-state">{auth.isLoading ? 'loading' : auth.authError ? 'unavailable' : auth.user?.user_id || 'anonymous'}</output>
    <output data-testid="issue-capability">{String(auth.hasCapability('org:issue'))}</output>
    <output data-testid="location">{location.pathname}{location.search}{location.hash}</output>
    <button onClick={() => auth.refreshUser()}>Refresh identity</button>
  </>;
}

function TestApplication() {
  return <AuthProvider>
    <ConsoleContext.Provider value={{
      mode: 'org', activeOrgId: null, memberships: [], membershipsLoaded: true,
      isLoading: false, membershipLoadError: null,
    } as any}>
      <SessionProbe />
      <Routes>
        <Route path="/console/login" element={<LoginPage fallbackRedirectTo="/console" />} />
        <Route path="/private" element={<ProtectedRoute redirectTo="/console/login"><h1>Private content</h1></ProtectedRoute>} />
        <Route path="/console/applicant/invitation" element={<ApplicantConsoleRoute redirectTo="/console/login"><h1>Invitation content</h1></ApplicantConsoleRoute>} />
        <Route path="/console/org/templates/credentials/new" element={<OrgConsoleRoute redirectTo="/console/login"><h1>Credential template</h1></OrgConsoleRoute>} />
        <Route path="/console/org/setup" element={<h1>Unexpected setup redirect</h1>} />
      </Routes>
    </ConsoleContext.Provider>
  </AuthProvider>;
}

describe('authentication unavailable recovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getCurrentUser).mockReset();
    window.localStorage.clear();
  });

  it.each([
    ['AUTH_NETWORK', 'Check your connection'],
    ['AUTH_TIMEOUT', 'took too long'],
    ['AUTH_CONFIGURATION', 'contact the operator'],
    ['AUTH_RESPONSE_INVALID', 'contact the operator'],
    ['AUTH_UNAVAILABLE', 'temporarily unavailable'],
  ])('shows actionable %s guidance instead of starting sign-in', async (code, guidance) => {
    vi.mocked(getCurrentUser).mockRejectedValue(unavailable(code));
    renderWithRouter(<TestApplication />, { initialEntries: ['/console/login?next=%2Fprivate%3Finvite%3Dkept'] });

    expect(await screen.findByRole('heading', { name: 'Sign-in is temporarily unavailable' })).toBeVisible();
    expect(screen.getByRole('alert')).toHaveTextContent(guidance);
    expect(screen.queryByText('private upstream details')).not.toBeInTheDocument();
    expect(screen.getByTestId('issue-capability')).toHaveTextContent('false');
    expect(initiateLogin).not.toHaveBeenCalled();
    expect(screen.getByTestId('location')).toHaveTextContent('/console/login?next=%2Fprivate%3Finvite%3Dkept');
  });

  it.each([
    '/private?invite=invitation-1#details',
    '/console/applicant/invitation?invite=invitation-1#details',
    '/console/org/templates/credentials/new?invite=invitation-1#details',
  ])('keeps %s through failure, retry and anonymous login handoff', async destination => {
    const retry = deferred<typeof anonymous>();
    vi.mocked(getCurrentUser).mockRejectedValueOnce(unavailable()).mockReturnValueOnce(retry.promise);
    const { user } = renderWithRouter(<TestApplication />, { initialEntries: [destination] });
    await screen.findByRole('heading', { name: 'Sign-in is temporarily unavailable' });
    expect(screen.getByTestId('location')).toHaveTextContent(destination);
    expect(screen.queryByRole('heading', { name: /Private content|Invitation content|Credential template|Unexpected setup/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Retry sign-in check' }));
    expect(screen.getByRole('button', { name: 'Checking sign-in…' })).toBeDisabled();
    expect(screen.getByTestId('location')).toHaveTextContent(destination);
    expect(initiateLogin).not.toHaveBeenCalled();
    await act(async () => retry.resolve(anonymous));
    await waitFor(() => expect(initiateLogin).toHaveBeenCalledWith(destination, expect.any(String)));
    expect(initiateLogin).toHaveBeenCalledTimes(1);
  });

  it('recovers to the existing protected page after a successful session retry', async () => {
    vi.mocked(getCurrentUser).mockRejectedValueOnce(unavailable()).mockResolvedValueOnce(authenticated);
    const { user } = renderWithRouter(<TestApplication />, { initialEntries: ['/private?invite=kept'] });
    await user.click(await screen.findByRole('button', { name: 'Retry sign-in check' }));
    expect(await screen.findByRole('heading', { name: 'Private content' })).toBeVisible();
    expect(screen.getByTestId('location')).toHaveTextContent('/private?invite=kept');
    expect(screen.getByTestId('issue-capability')).toHaveTextContent('true');
    expect(initiateLogin).not.toHaveBeenCalled();
  });

  it('keeps the next query destination when a login-page retry confirms an anonymous session', async () => {
    vi.mocked(getCurrentUser).mockRejectedValueOnce(unavailable()).mockResolvedValueOnce(anonymous);
    const { user } = renderWithRouter(<TestApplication />, {
      initialEntries: ['/console/login?next=%2Fconsole%2Fapplicant%2Finvitation%3Finvite%3Doriginal%23accept'],
    });
    await user.click(await screen.findByRole('button', { name: 'Retry sign-in check' }));
    await waitFor(() => expect(initiateLogin).toHaveBeenCalledWith('/console/applicant/invitation?invite=original#accept', expect.any(String)));
  });

  it('clears a known identity and its grants if a strict refresh cannot confirm the session', async () => {
    vi.mocked(getCurrentUser).mockResolvedValueOnce(authenticated).mockRejectedValueOnce(unavailable());
    const { user } = renderWithRouter(<TestApplication />, { initialEntries: ['/private'] });
    await screen.findByRole('heading', { name: 'Private content' });
    await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
    await screen.findByRole('heading', { name: 'Sign-in is temporarily unavailable' });
    expect(screen.queryByRole('heading', { name: 'Private content' })).not.toBeInTheDocument();
    expect(screen.getByTestId('issue-capability')).toHaveTextContent('false');
    expect(initiateLogin).not.toHaveBeenCalled();
  });

  it('ignores a stale failed retry after a newer identity check succeeds', async () => {
    const oldRetry = deferred<typeof authenticated>();
    vi.mocked(getCurrentUser).mockRejectedValueOnce(unavailable()).mockReturnValueOnce(oldRetry.promise).mockResolvedValueOnce(authenticated);
    const { user } = renderWithRouter(<TestApplication />, { initialEntries: ['/private'] });
    await user.click(await screen.findByRole('button', { name: 'Retry sign-in check' }));
    await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
    await screen.findByRole('heading', { name: 'Private content' });
    await act(async () => oldRetry.reject(unavailable('AUTH_NETWORK')));
    expect(screen.getByTestId('auth-state')).toHaveTextContent('confirmed-user');
    expect(screen.queryByRole('heading', { name: 'Sign-in is temporarily unavailable' })).not.toBeInTheDocument();
  });

  it('ignores a stale successful retry after a newer session check fails', async () => {
    const oldRetry = deferred<typeof authenticated>();
    vi.mocked(getCurrentUser).mockRejectedValueOnce(unavailable()).mockReturnValueOnce(oldRetry.promise).mockRejectedValueOnce(unavailable('AUTH_CONFIGURATION'));
    const { user } = renderWithRouter(<TestApplication />, { initialEntries: ['/private'] });
    await user.click(await screen.findByRole('button', { name: 'Retry sign-in check' }));
    await user.click(screen.getByRole('button', { name: 'Refresh identity' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('contact the operator'));
    await act(async () => oldRetry.resolve(authenticated));
    expect(screen.getByTestId('auth-state')).toHaveTextContent('unavailable');
    expect(screen.getByTestId('issue-capability')).toHaveTextContent('false');
    expect(screen.queryByRole('heading', { name: 'Private content' })).not.toBeInTheDocument();
    expect(initiateLogin).not.toHaveBeenCalled();
  });
});
