import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

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

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
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

describe('JoinOrganizationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockUseAuth.mockReturnValue({
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
    vi.restoreAllMocks();
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
      expect(setActiveOrgId).toHaveBeenCalledWith('org-1');
    });

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
      expect(setActiveOrgId).toHaveBeenCalledWith('org-1');
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
