import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

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

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
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

    expect(await screen.findByText('No Organizations Yet')).toBeInTheDocument();
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

    expect(await screen.findByText('No Organizations Yet')).toBeInTheDocument();

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

    expect(await screen.findByText('No Organizations Yet')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    expect(mockNavigate).toHaveBeenCalledWith('/console/organizations/create?returnTo=%2Fconsole%2Forg%2Fsettings');
  });
});
