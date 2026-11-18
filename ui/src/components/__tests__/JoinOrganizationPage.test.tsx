import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@test/utils';

import JoinOrganizationPage from '../pages/JoinOrganizationPage';

const {
  mockNavigate,
  mockSearchParams,
  mockUseAuth,
  mockConsoleContext,
  mockDiscoverOrganizations,
  mockGetOrganization,
  mockJoinByCode,
  mockJoinOrganization,
  mockValidateOrganizationInvitation,
  mockAcceptOrganizationInvitation,
  mockGetErrorMessage,
  mockRedirectBrowser,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockUseAuth: vi.fn(),
  mockConsoleContext: vi.fn(),
  mockDiscoverOrganizations: vi.fn(),
  mockGetOrganization: vi.fn(),
  mockJoinByCode: vi.fn(),
  mockJoinOrganization: vi.fn(),
  mockValidateOrganizationInvitation: vi.fn(),
  mockAcceptOrganizationInvitation: vi.fn(),
  mockGetErrorMessage: vi.fn(),
  mockRedirectBrowser: vi.fn(),
}));

vi.mock('../../application/routing/appHandoff', () => ({
  redirectBrowser: (...args: unknown[]) => mockRedirectBrowser(...args),
  shouldBrowserRedirect: () => false,
}));

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [mockSearchParams()],
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockConsoleContext(),
}));

vi.mock('../../services/organizationsApi', () => ({
  acceptOrganizationInvitation: (...args: unknown[]) => mockAcceptOrganizationInvitation(...args),
  discoverOrganizations: (...args: unknown[]) => mockDiscoverOrganizations(...args),
  getErrorMessage: (...args: unknown[]) => mockGetErrorMessage(...args),
  getOrganization: (...args: unknown[]) => mockGetOrganization(...args),
  joinByCode: (...args: unknown[]) => mockJoinByCode(...args),
  joinOrganization: (...args: unknown[]) => mockJoinOrganization(...args),
  validateOrganizationInvitation: (...args: unknown[]) => mockValidateOrganizationInvitation(...args),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

type JoinFlow = 'code' | 'open' | 'invitation';
function configureFlow(flow: JoinFlow) {
  mockSearchParams.mockReturnValue(new URLSearchParams(flow === 'code'
    ? 'mode=code' : flow === 'open' ? 'orgId=org-1' : 'inviteToken=token-1'));
  return flow === 'code' ? mockJoinByCode : flow === 'open' ? mockJoinOrganization : mockAcceptOrganizationInvitation;
}
async function startFlow(flow: JoinFlow) {
  const view = render(<JoinOrganizationPage />);
  if (flow === 'code') await view.user.type(screen.getByPlaceholderText('Enter 8-character join code'), 'ABCD1234');
  const label = flow === 'code' ? 'Join via Code' : flow === 'open' ? 'Join Organization' : 'Accept invitation';
  await view.user.click(await screen.findByRole('button', { name: label }));
  return view;
}

describe('JoinOrganizationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockUseAuth.mockReturnValue({
      user: { user_id: 'user-a' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
    });
    mockConsoleContext.mockReturnValue({
      refreshMemberships: vi.fn().mockResolvedValue(undefined),
      setActiveOrgId: vi.fn().mockResolvedValue(undefined),
    });
    mockDiscoverOrganizations.mockResolvedValue([
      {
        id: 'org-1',
        name: 'Acme',
        description: 'Trusted issuer',
        join_mechanism: 'open',
        requires_approval: false,
      },
    ]);
    mockGetOrganization.mockResolvedValue(null);
    mockJoinByCode.mockResolvedValue({
      organization: { id: 'org-1', name: 'Acme' },
      membership: { status: 'active' },
    });
    mockJoinOrganization.mockResolvedValue({ membership: { status: 'active' } });
    mockValidateOrganizationInvitation.mockResolvedValue({
      valid: true,
      organization_id: 'org-1',
      organization_name: 'Acme',
      email: 'person@example.com',
    });
    mockAcceptOrganizationInvitation.mockResolvedValue({
      organization_id: 'org-1',
      organization_name: 'Acme',
    });
    mockGetErrorMessage.mockImplementation((error?: { message?: string }) => error?.message || 'Unknown error');
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...window.location,
        pathname: '/organizations/join',
        search: '?mode=code',
      },
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it.each(['code', 'open', 'invitation'] as const)('handles canceled %s membership refresh without selecting, reporting or redirecting', async flow => {
    configureFlow(flow);
    const canceled = Object.assign(new Error('The console session or selection changed.'), { name: 'AbortError' });
    const refreshMemberships = vi.fn().mockRejectedValue(canceled);
    const setActiveOrgId = vi.fn();
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});

    await startFlow(flow);
    await waitFor(() => expect(refreshMemberships).toHaveBeenCalledTimes(1));

    expect(setActiveOrgId).not.toHaveBeenCalled();
    expect(logged.mock.calls.flat()).not.toContain(canceled);
    expect(screen.queryByText(canceled.message)).not.toBeInTheDocument();
    expect(mockRedirectBrowser).not.toHaveBeenCalled();
    if (flow === 'invitation') expect(screen.getByRole('button', { name: 'Accept invitation' })).toBeEnabled();
  });

  it.each(['code', 'open', 'invitation'] as const)('stops the %s chain if the page unmounts before the mutation completes', async flow => {
    const mutation = configureFlow(flow);
    const result = deferred<unknown>();
    mutation.mockReturnValue(result.promise);
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });
    const view = await startFlow(flow);
    await waitFor(() => expect(mutation).toHaveBeenCalledTimes(1));

    view.unmount();
    await act(async () => result.resolve({
      organization: { id: 'org-1', name: 'Acme' }, organization_id: 'org-1',
      organization_name: 'Acme', membership: { status: 'active' },
    }));

    expect(refreshMemberships).not.toHaveBeenCalled();
    expect(setActiveOrgId).not.toHaveBeenCalled();
    expect(mockRedirectBrowser).not.toHaveBeenCalled();
  });

  it('stops an old native account response before refreshing or selecting for a new account', async () => {
    configureFlow('open');
    const result = deferred<unknown>();
    mockJoinOrganization.mockReturnValue(result.promise);
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });
    const view = await startFlow('open');
    mockUseAuth.mockReturnValue({ user: { user_id: 'user-b' }, isAuthenticated: true, isLoading: false, login: vi.fn() });
    view.rerender(<JoinOrganizationPage />);
    await act(async () => result.resolve({ membership: { status: 'active' } }));
    expect(refreshMemberships).not.toHaveBeenCalled();
    expect(setActiveOrgId).not.toHaveBeenCalled();
    expect(screen.queryByText('You joined Acme')).not.toBeInTheDocument();
    expect(mockRedirectBrowser).not.toHaveBeenCalled();
  });

  it('revalidates an accepting invitation for a replacement account instead of leaving it busy', async () => {
    configureFlow('invitation');
    const acceptance = deferred<unknown>();
    mockAcceptOrganizationInvitation.mockReturnValue(acceptance.promise);
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });
    const view = await startFlow('invitation');
    await waitFor(() => expect(mockAcceptOrganizationInvitation).toHaveBeenCalledTimes(1));
    mockUseAuth.mockReturnValue({ user: { user_id: 'user-b' }, isAuthenticated: true, isLoading: false, login: vi.fn() });
    view.rerender(<JoinOrganizationPage />);

    await waitFor(() => expect(mockValidateOrganizationInvitation).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('button', { name: 'Accept invitation' })).toBeEnabled();
    await act(async () => acceptance.resolve({ organization_id: 'org-1', organization_name: 'Acme' }));
    expect(refreshMemberships).not.toHaveBeenCalled();
    expect(setActiveOrgId).not.toHaveBeenCalled();
    expect(mockRedirectBrowser).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Accept invitation' })).toBeEnabled();
  });

  it.each([
    { change: 'account', outcome: 'invalid' },
    { change: 'target', outcome: 'invalid' },
    { change: 'target', outcome: 'success' },
    { change: 'target', outcome: 'failure' },
  ])('ignores previous invitation validation $outcome after the $change changes', async ({ change, outcome }) => {
    configureFlow('invitation');
    const previous = deferred<unknown>();
    mockValidateOrganizationInvitation.mockReturnValueOnce(previous.promise);
    const view = render(<JoinOrganizationPage />);
    await waitFor(() => expect(mockValidateOrganizationInvitation).toHaveBeenCalledTimes(1));
    if (change === 'account') {
      mockUseAuth.mockReturnValue({ user: { user_id: 'user-b' }, isAuthenticated: true, isLoading: false, login: vi.fn() });
    } else {
      mockSearchParams.mockReturnValue(new URLSearchParams('inviteToken=token-2'));
    }
    mockValidateOrganizationInvitation.mockResolvedValue({ valid: true, organization_id: 'org-2', organization_name: 'Beta' });
    view.rerender(<JoinOrganizationPage />);
    expect(await screen.findByRole('button', { name: 'Accept invitation' })).toBeEnabled();
    expect(screen.getByRole('heading', { name: 'Join Beta' })).toBeVisible();
    await act(async () => {
      if (outcome === 'failure') previous.reject(new Error('Previous invitation expired'));
      else if (outcome === 'success') previous.resolve({ valid: true, organization_id: 'org-1', organization_name: 'Acme' });
      else previous.resolve({ valid: false, reason: 'Previous account result' });
      await previous.promise.catch(() => {});
    });
    expect(screen.getByRole('button', { name: 'Accept invitation' })).toBeEnabled();
    expect(screen.getByRole('heading', { name: 'Join Beta' })).toBeVisible();
    expect(screen.queryByText('Join Acme')).not.toBeInTheDocument();
    expect(screen.queryByText('Previous account result')).not.toBeInTheDocument();
    expect(screen.queryByText('Previous invitation expired')).not.toBeInTheDocument();
  });

  it.each(['unmount', 'account change', 'target change', 'current page'] as const)('owns the delayed redirect across %s', async change => {
    configureFlow('open');
    const view = render(<JoinOrganizationPage />);
    const button = await screen.findByRole('button', { name: 'Join Organization' });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    await act(async () => { fireEvent.click(button); });
    expect(screen.getByText('You joined Acme')).toBeInTheDocument();

    if (change === 'unmount') view.unmount();
    if (change === 'account change') {
      mockUseAuth.mockReturnValue({ user: { user_id: 'user-b' }, isAuthenticated: true, isLoading: false, login: vi.fn() });
      view.rerender(<JoinOrganizationPage />);
    }
    if (change === 'target change') {
      mockSearchParams.mockReturnValue(new URLSearchParams('orgId=org-2'));
      view.rerender(<JoinOrganizationPage />);
    }
    await act(async () => { await vi.advanceTimersByTimeAsync(1200); });

    if (change === 'current page') expect(mockRedirectBrowser).toHaveBeenCalledExactlyOnceWith('/console', { replace: false });
    else expect(mockRedirectBrowser).not.toHaveBeenCalled();
  });

  it.each([
    { flow: 'open', step: 'join' },
    { flow: 'invitation', step: 'join' },
    { flow: 'open', step: 'refresh' },
    { flow: 'open', step: 'selection' },
  ] as const)('stops a previous $flow target during $step', async ({ flow, step }) => {
    const mutation = configureFlow(flow);
    const result = deferred<unknown>();
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });
    const operation = step === 'join' ? mutation : step === 'refresh' ? refreshMemberships : setActiveOrgId;
    operation.mockReturnValueOnce(result.promise);
    const view = await startFlow(flow);
    await waitFor(() => expect(operation).toHaveBeenCalledTimes(1));
    mockSearchParams.mockReturnValue(new URLSearchParams(flow === 'open' ? 'orgId=org-2' : 'inviteToken=token-2'));
    mockGetOrganization.mockResolvedValue({ id: 'org-2', name: 'Beta', join_mechanism: 'open' });
    mockValidateOrganizationInvitation.mockResolvedValue({ valid: true, organization_id: 'org-2', organization_name: 'Beta' });
    view.rerender(<JoinOrganizationPage />);
    await screen.findByRole('button', { name: flow === 'open' ? 'Join Organization' : 'Accept invitation' });
    await act(async () => result.resolve({ membership: { status: 'active' }, organization_id: 'org-1', organization_name: 'Acme' }));
    if (step === 'join') expect(refreshMemberships).not.toHaveBeenCalled();
    if (step !== 'selection') expect(setActiveOrgId).not.toHaveBeenCalled();
    expect(mockRedirectBrowser).not.toHaveBeenCalled();
    expect(screen.queryByText('You joined Acme')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: flow === 'open' ? 'Beta' : 'Join Beta' })).toBeVisible();
    expect(screen.getByRole('button', { name: flow === 'open' ? 'Join Organization' : 'Accept invitation' })).toBeEnabled();
    expect(screen.queryByText(/The view or action changed|The console session or selection changed/)).not.toBeInTheDocument();
  });

  it('does not let a previous discovery response replace the new query target', async () => {
    configureFlow('open');
    const previous = deferred<unknown>();
    mockDiscoverOrganizations.mockReturnValueOnce(previous.promise).mockResolvedValue([
      { id: 'org-2', name: 'Beta', join_mechanism: 'open', requires_approval: false },
    ]);
    const view = render(<JoinOrganizationPage />);
    await waitFor(() => expect(mockDiscoverOrganizations).toHaveBeenCalledTimes(1));
    mockSearchParams.mockReturnValue(new URLSearchParams('orgId=org-2'));
    view.rerender(<JoinOrganizationPage />);
    await screen.findByRole('heading', { name: 'Beta' });
    await act(async () => previous.resolve([
      { id: 'org-1', name: 'Acme', join_mechanism: 'open', requires_approval: false },
    ]));
    expect(screen.getByRole('heading', { name: 'Beta' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Acme' })).not.toBeInTheDocument();
  });

  it.each(['query', 'account'])('does not let previous organization details replace or join the new %s target', async change => {
    configureFlow('open');
    const previous = deferred<unknown>();
    mockDiscoverOrganizations.mockResolvedValue([]);
    const newOrgId = change === 'query' ? 'org-2' : 'org-1';
    mockGetOrganization.mockReturnValueOnce(previous.promise).mockResolvedValue({
      id: newOrgId, name: 'Beta', join_mechanism: 'open', requires_approval: false,
    });
    const view = render(<JoinOrganizationPage />);
    await waitFor(() => expect(mockGetOrganization).toHaveBeenCalledWith('org-1'));
    if (change === 'query') mockSearchParams.mockReturnValue(new URLSearchParams('orgId=org-2'));
    else mockUseAuth.mockReturnValue({ user: { user_id: 'user-b' }, isAuthenticated: true, isLoading: false, login: vi.fn() });
    view.rerender(<JoinOrganizationPage />);
    await screen.findByRole('heading', { name: 'Beta' });
    await act(async () => previous.resolve({ id: 'org-1', name: 'Acme', join_mechanism: 'open' }));
    expect(screen.getByRole('heading', { name: 'Beta' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Acme' })).not.toBeInTheDocument();
    await view.user.click(screen.getByRole('button', { name: 'Join Organization' }));
    expect(mockJoinOrganization).toHaveBeenCalledExactlyOnceWith(newOrgId);
  });

  it('preserves a current join failure instead of treating it as cancellation', async () => {
    configureFlow('open');
    const error = new Error('Join service unavailable');
    mockJoinOrganization.mockRejectedValueOnce(error);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const view = await startFlow('open');
    expect(await screen.findByText(error.message)).toBeInTheDocument();
    expect(logged.mock.calls.flat()).toContain(error);
    expect(mockRedirectBrowser).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Join Organization' })).toBeEnabled();
    await view.user.click(screen.getByRole('button', { name: 'Join Organization' }));
    expect(await screen.findByText('You joined Acme')).toBeVisible();
  });

  it('validates and accepts invitation links', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('inviteToken=token-1'));
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });

    const { user } = render(<JoinOrganizationPage />);

    expect(await screen.findByText('Join Acme')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Accept invitation' }));

    await waitFor(() => {
      expect(mockAcceptOrganizationInvitation).toHaveBeenCalledWith('token-1');
      expect(refreshMemberships).toHaveBeenCalled();
      expect(setActiveOrgId).toHaveBeenCalledWith('org-1', null, { navigate: false });
    });

    expect(await screen.findByRole('heading', { name: 'You joined Acme' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Go to Organization Console' })).toBeEnabled();

    await waitFor(() => {
      expect(mockRedirectBrowser).toHaveBeenCalledWith('/console', { replace: false });
    }, { timeout: 2500 });
  });

  it('redirects unauthenticated users to login when joining by code', async () => {
    const login = vi.fn();
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      login,
    });
    mockSearchParams.mockReturnValue(new URLSearchParams('mode=code'));

    const { user } = render(<JoinOrganizationPage />);

    await user.type(screen.getByPlaceholderText('Enter 8-character join code'), 'abcd1234');
    await user.click(screen.getByRole('button', { name: 'Join via Code' }));

    expect(login).toHaveBeenCalledWith('/organizations/join?mode=code');
    expect(mockJoinByCode).not.toHaveBeenCalled();
  });

  it('joins an open organization from the preview pane', async () => {
    const refreshMemberships = vi.fn().mockResolvedValue(undefined);
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ refreshMemberships, setActiveOrgId });
    mockSearchParams.mockReturnValue(new URLSearchParams('orgId=org-1'));

    const { user } = render(<JoinOrganizationPage />);

    expect(await screen.findByText('Organization Preview')).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Join Organization' }));

    await waitFor(() => {
      expect(mockJoinOrganization).toHaveBeenCalledWith('org-1');
      expect(refreshMemberships).toHaveBeenCalled();
      expect(setActiveOrgId).toHaveBeenCalledWith('org-1', null, { navigate: false });
    });

    await waitFor(() => {
      expect(mockRedirectBrowser).toHaveBeenCalledWith('/console', { replace: false });
    }, { timeout: 2500 });
  });

  it('does not show a global error when stale org details fail but discovery still loads', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('orgId=22222222-2222-2222-2222-222222222222'));
    mockDiscoverOrganizations.mockResolvedValue([
      {
        id: 'demo-org',
        name: 'Demo Vendor Org',
        description: 'Demo organization for context switching and join/discovery demonstrations',
        join_mechanism: 'invite',
        requires_approval: false,
      },
    ]);
    mockGetOrganization.mockRejectedValue({ status: 500, message: 'Server exploded' });
    mockGetErrorMessage.mockReturnValue('An unexpected error occurred. Please try again.');

    const { user } = render(<JoinOrganizationPage />);

    expect(await screen.findByText('Demo Vendor Org')).toBeInTheDocument();

    await waitFor(() => {
      expect(mockGetOrganization).toHaveBeenCalledWith('22222222-2222-2222-2222-222222222222');
      expect(screen.queryByText('An unexpected error occurred. Please try again.')).not.toBeInTheDocument();
    });

    await user.click(screen.getByText('Demo Vendor Org'));

    expect(screen.getByRole('heading', { name: 'Demo Vendor Org' })).toBeInTheDocument();
  });

  it('uses the configured management paths after a pending join request', async () => {
    mockJoinOrganization.mockResolvedValue({ membership: { status: 'pending' } });
    mockSearchParams.mockReturnValue(new URLSearchParams('orgId=org-1'));

    const { user } = render(
      <JoinOrganizationPage managePath="/console/organizations" discoverPath="/console/organizations/discover" />,
    );

    await user.click(await screen.findByRole('button', { name: 'Join Organization' }));

    expect(await screen.findByText('Request submitted to Acme')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'View My Organizations' }));
    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations');

    await user.click(screen.getByRole('button', { name: 'Discover More Organizations' }));
    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations/discover');
  });
});
