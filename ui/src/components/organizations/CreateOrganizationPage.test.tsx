import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import CreateOrganizationPage from './CreateOrganizationPage';

const {
  mockNavigate,
  mockSearchParams,
  mockCreateOrganization,
  mockRefreshMemberships,
  mockSetActiveOrgId,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockCreateOrganization: vi.fn(),
  mockRefreshMemberships: vi.fn(),
  mockSetActiveOrgId: vi.fn(),
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
  useConsole: () => ({
    refreshMemberships: mockRefreshMemberships,
    setActiveOrgId: mockSetActiveOrgId,
  }),
}));

vi.mock('../../services/organizationsApi', () => ({
  createOrganization: (...args: unknown[]) => mockCreateOrganization(...args),
}));

describe('CreateOrganizationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockCreateOrganization.mockResolvedValue({ id: 'org-new' });
    mockRefreshMemberships.mockResolvedValue(undefined);
    mockSetActiveOrgId.mockResolvedValue(undefined);
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
      expect(mockSetActiveOrgId).toHaveBeenCalledWith('org-new');
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
});