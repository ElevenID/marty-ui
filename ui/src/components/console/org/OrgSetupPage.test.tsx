import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@test/utils';

import OrgSetupPage from './OrgSetupPage';

const {
  mockNavigate,
  mockSearchParams,
  mockUseConsole,
  mockUseAuth,
  mockGetMyOrganizations,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockUseConsole: vi.fn(),
  mockUseAuth: vi.fn(),
  mockGetMyOrganizations: vi.fn(),
}));

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [mockSearchParams()],
  };
});

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('../../../services/organizationsApi', () => ({
  getMyOrganizations: (...args: unknown[]) => mockGetMyOrganizations(...args),
}));

describe('OrgSetupPage', () => {
  beforeEach(() => {
    delete (window as any).__MARTY_RUNTIME_CONFIG__;
    vi.clearAllMocks();

    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockUseConsole.mockReturnValue({
      activeOrgId: null,
      memberships: [],
      membershipsLoaded: true,
      refreshMemberships: vi.fn().mockResolvedValue(undefined),
      setActiveOrgId: vi.fn().mockResolvedValue(undefined),
      setMode: vi.fn().mockResolvedValue(undefined),
    });
    mockUseAuth.mockReturnValue({
      organizationId: null,
      organizations: [],
      setActiveOrganizationId: vi.fn(),
    });
    mockGetMyOrganizations.mockResolvedValue([
      {
        id: 'marty-org',
        name: 'Marty',
        display_name: 'Marty',
        membership: {
          status: 'active',
          has_org_console_access: false,
          roles: [{ id: 'role-applicant', name: 'applicant', display_name: 'Applicant' }],
        },
      },
    ]);
  });

  it('excludes applicant-only memberships from organization-console selection', async () => {
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);

    mockUseConsole.mockReturnValue({
      activeOrgId: null,
      memberships: [],
      membershipsLoaded: true,
      refreshMemberships: vi.fn().mockResolvedValue(undefined),
      setActiveOrgId,
      setMode: vi.fn().mockResolvedValue(undefined),
    });

    render(<OrgSetupPage />);

    expect(await screen.findByText('No Console Memberships Yet')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Organization Console Access' })).toBeInTheDocument();
    expect(screen.queryByText('No Organizations Yet')).not.toBeInTheDocument();
    expect(screen.queryByText(/access credentials and start applying/i)).not.toBeInTheDocument();
    expect(screen.queryByText('Marty')).not.toBeInTheDocument();
    expect(setActiveOrgId).not.toHaveBeenCalled();
  });

  it('restores discover and join entry points in the empty setup state', async () => {
    mockGetMyOrganizations.mockResolvedValue([]);
    mockUseAuth.mockReturnValue({
      organizationId: null,
      organizations: [],
      setActiveOrganizationId: vi.fn(),
    });

    const { user } = render(<OrgSetupPage />);

    expect(await screen.findByText('No Console Memberships Yet')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Create Organization' }));
    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations/create');

    await user.click(screen.getByRole('button', { name: 'Discover Organizations' }));
    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations/discover');

    await user.click(screen.getByRole('button', { name: 'Use Join Code' }));
    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations/join?mode=code');
  });

  it('preserves returnTo when routing to the standalone create page', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('returnTo=/console/org/settings'));
    mockGetMyOrganizations.mockResolvedValue([]);

    const { user } = render(<OrgSetupPage />);

    expect(await screen.findByText('No Console Memberships Yet')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations/create?returnTo=%2Fconsole%2Forg%2Fsettings');
  });

  it('asks existing eligible members to choose an organization and retains the console action', async () => {
    const setActiveOrgId = vi.fn().mockResolvedValue(undefined);
    mockUseConsole.mockReturnValue({
      activeOrgId: null,
      memberships: [],
      membershipsLoaded: true,
      setActiveOrgId,
    });
    mockGetMyOrganizations.mockResolvedValue([{
      id: 'marty-org',
      display_name: 'Marty Identity Platform',
      membership: {
        status: 'active',
        has_org_console_access: true,
        roles: [{ name: 'admin', display_name: 'Administrator' }],
      },
    }]);
    const { user } = render(<OrgSetupPage />);

    expect(await screen.findByRole('heading', { name: 'Choose an Organization' })).toBeInTheDocument();
    expect(screen.getByText('Select an organization to open its organization console.')).toBeInTheDocument();
    expect(screen.queryByText('Join an Organization')).not.toBeInTheDocument();
    expect(screen.queryByText(/access credentials and start applying/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open Org Console' }));

    expect(setActiveOrgId).toHaveBeenCalledWith('marty-org', null, { navigate: false });
    expect(mockNavigate).toHaveBeenCalledWith('/console/org');
  });

  it('does not navigate when the view unmounts between selection completion and the caller continuation', async () => {
    let resolveSelection!: () => void;
    const selection = new Promise<void>((resolve) => { resolveSelection = resolve; });
    const setActiveOrgId = vi.fn().mockReturnValue(selection);
    mockUseConsole.mockReturnValue({
      activeOrgId: null,
      memberships: [],
      membershipsLoaded: true,
      setActiveOrgId,
    });
    mockGetMyOrganizations.mockResolvedValue([{
      id: 'marty-org',
      display_name: 'Marty Identity Platform',
      membership: {
        status: 'active',
        has_org_console_access: true,
        roles: [{ name: 'admin', display_name: 'Administrator' }],
      },
    }]);
    const { user, unmount } = render(<OrgSetupPage />);
    await user.click(await screen.findByRole('button', { name: 'Open Org Console' }));
    expect(setActiveOrgId).toHaveBeenCalledWith('marty-org', null, { navigate: false });

    // The awaited scope helper resumes first; the view then unmounts before its
    // caller's continuation. Navigation must check the view at its own boundary.
    const unmounted = selection.then(() => unmount());
    await act(async () => {
      resolveSelection();
      await unmounted;
    });

    expect(mockNavigate).not.toHaveBeenCalled();
  });
});
