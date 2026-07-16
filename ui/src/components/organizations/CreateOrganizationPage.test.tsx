import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import CreateOrganizationPage from './CreateOrganizationPage';

const {
  mockNavigate,
  mockSearchParams,
  mockCreateOrganization,
  mockRefreshMemberships,
  mockSetActiveOrgId,
  mockReloadConsoleState,
  mockUseConsole,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockCreateOrganization: vi.fn(),
  mockRefreshMemberships: vi.fn(),
  mockSetActiveOrgId: vi.fn(),
  mockReloadConsoleState: vi.fn(),
  mockUseConsole: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [mockSearchParams()],
  };
});

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}));

vi.mock('../../services/organizationsApi', () => ({
  createOrganization: (...args: unknown[]) => mockCreateOrganization(...args),
}));

describe('CreateOrganizationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockCreateOrganization.mockResolvedValue({ id: 'org-new' });
    mockRefreshMemberships.mockResolvedValue([{ id: 'org-new' }]);
    mockSetActiveOrgId.mockResolvedValue(undefined);
    mockUseConsole.mockReturnValue({
      refreshMemberships: mockRefreshMemberships,
      setActiveOrgId: mockSetActiveOrgId,
      membershipLoadError: null,
      isOrgBootstrapRequired: false,
      isLoading: false,
      reloadConsoleState: mockReloadConsoleState,
    });
  });

  it('creates an organization with discovery and membership settings', async () => {
    const { user } = render(<CreateOrganizationPage />);

    await user.type(screen.getByLabelText('Organization Slug'), 'acme-travel');
    await user.type(screen.getByLabelText('Display Name'), 'Acme Travel');
    await user.type(screen.getByLabelText('Description'), 'Trusted travel credentials');
    await user.type(screen.getByLabelText('Contact Email'), 'ops@example.com');
    await user.click(screen.getByLabelText('Discoverable'));
    await user.click(screen.getByLabelText(/Open/));
    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    await waitFor(() => {
      expect(mockCreateOrganization).toHaveBeenCalledWith(expect.objectContaining({
        name: 'acme-travel',
        display_name: 'Acme Travel',
        description: 'Trusted travel credentials',
        contact_email: 'ops@example.com',
        org_type: 'enterprise',
        jurisdiction: 'US',
        is_discoverable: true,
        visibility: 'PUBLIC',
        membership_mode: 'open',
      }));
      expect(mockRefreshMemberships).toHaveBeenCalled();
      expect(mockSetActiveOrgId).toHaveBeenCalledWith('org-new', [{ id: 'org-new' }]);
      expect(mockNavigate).toHaveBeenCalledWith('/console/org');
    });
  });

  it('honors returnTo after creation', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('returnTo=/console/org/settings'));
    const { user } = render(<CreateOrganizationPage />);

    await user.type(screen.getByLabelText('Organization Slug'), 'acme-travel');
    await user.type(screen.getByLabelText('Display Name'), 'Acme Travel');
    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/org/settings');
    });
  });

  it('activates the created organization even when the membership refresh is stale', async () => {
    mockCreateOrganization.mockResolvedValueOnce({
      organization: {
        id: 'org-new',
        name: 'acme-travel',
        display_name: 'Acme Travel',
      },
      membership: {
        roles: [{ name: 'owner' }],
        has_org_console_access: true,
      },
    });
    mockRefreshMemberships.mockResolvedValueOnce([{ id: 'marty-org', name: 'Marty' }]);
    const { user } = render(<CreateOrganizationPage />);

    await user.type(screen.getByLabelText('Organization Slug'), 'acme-travel');
    await user.type(screen.getByLabelText('Display Name'), 'Acme Travel');
    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    await waitFor(() => {
      expect(mockSetActiveOrgId).toHaveBeenCalledWith('org-new', [
        { id: 'marty-org', name: 'Marty' },
        {
          id: 'org-new',
          name: 'acme-travel',
          display_name: 'Acme Travel',
          membership: {
            roles: [{ name: 'owner' }],
            has_org_console_access: true,
          },
        },
      ]);
      expect(mockNavigate).toHaveBeenCalledWith('/console/org');
    });
  });

  it('shows configuration-disabled errors returned by the backend', async () => {
    const backendError = new Error('Forbidden') as Error & {
      status?: number;
      response?: { error_description?: string; message_id?: string };
      requestId?: string;
    };
    backendError.status = 403;
    backendError.response = {
      error_description: 'Organization creation is disabled for this deployment',
      message_id: 'msg-disabled',
    };
    mockCreateOrganization.mockRejectedValueOnce(backendError);

    const { user } = render(<CreateOrganizationPage />);

    await user.type(screen.getByLabelText('Organization Slug'), 'acme-travel');
    await user.type(screen.getByLabelText('Display Name'), 'Acme Travel');
    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    expect(await screen.findByText(/Organization creation is disabled by this deployment configuration/)).toBeInTheDocument();
    expect(screen.getByText(/Message ID: msg-disabled/)).toBeInTheDocument();
  });

  it('shows the organization-service unavailable state instead of the create form when org bootstrap fails', () => {
    mockUseConsole.mockReturnValue({
      refreshMemberships: mockRefreshMemberships,
      setActiveOrgId: mockSetActiveOrgId,
      membershipLoadError: {
        message: 'Organization service unavailable',
        messageId: 'msg-503',
      },
      isOrgBootstrapRequired: true,
      isLoading: false,
      reloadConsoleState: mockReloadConsoleState,
    });

    render(<CreateOrganizationPage />);

    expect(screen.getByText('Organization console unavailable')).toBeInTheDocument();
    expect(screen.getByText('Organization service unavailable')).toBeInTheDocument();
    expect(screen.getByText('Message ID: msg-503')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create Organization' })).not.toBeInTheDocument();
  });
});
