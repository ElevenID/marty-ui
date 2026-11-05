import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';
import { fireEvent, waitFor, within } from '@testing-library/react';

import ProfilePage from '../ProfilePage';

const passkeyMock = vi.hoisted(() => ({ available: false, managementUrl: undefined as string | undefined, start: vi.fn() }));

const mockSetActiveOrganizationId = vi.fn();
const mockSetActiveOrgId = vi.fn();
const mockRefreshUser = vi.fn();

vi.mock('../../services/authApi', () => ({
  updateProfilePicture: vi.fn(),
  startPasskeyEnrollment: passkeyMock.start,
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      id: 'user-1',
      email: 'applicant@example.com',
      name: 'Ada Lovelace',
      applicant_id: 'app-1',
      roles: ['applicant'],
      passkey_enrollment_available: passkeyMock.available,
      passkey_management_url: passkeyMock.managementUrl,
    },
    isAdministrator: false,
    isApplicant: true,
    organizationId: 'org-1',
    organizations: [
      {
        id: 'org-1',
        name: 'Marty Org',
        membership: {
          status: 'active',
          roles: [{ id: 'role-1', name: 'admin', display_name: 'Administrator' }],
          has_org_console_access: true,
        },
      },
      {
        id: 'org-2',
        name: 'Open Federation',
        membership: {
          status: 'pending',
          roles: [{ id: 'role-2', name: 'applicant', display_name: 'Applicant' }],
          has_org_console_access: false,
        },
      },
    ],
    setActiveOrganizationId: mockSetActiveOrganizationId,
    refreshUser: mockRefreshUser,
  }),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: 'org-1',
    setActiveOrgId: mockSetActiveOrgId,
  }),
}));

describe('ProfilePage', () => {
  beforeEach(() => { passkeyMock.available = false; passkeyMock.managementUrl = undefined; passkeyMock.start.mockReset(); });

  it('opens the server-selected native console and explains the remaining-method safeguard', () => {
    passkeyMock.available = true;
    passkeyMock.managementUrl = 'https://identity.example/realms/11id/account/account-security/signing-in';
    render(<ProfilePage />);
    expect(screen.getByRole('link', { name: 'Manage passkeys' })).toHaveAttribute('href', passkeyMock.managementUrl);
    expect(screen.getByText(/Keep another passkey or a working password/)).toBeInTheDocument();
  });

  it('shows email confirmation and prevents duplicate requests on the badge enrollment path', async () => {
    passkeyMock.available = true;
    passkeyMock.start.mockResolvedValue({ email_sent: true });
    render(<ProfilePage />);
    fireEvent.click(screen.getByRole('button', { name: 'Create a passkey' }));
    await waitFor(() => expect(screen.getByText(/Check your account email/)).toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Enrollment email sent' })).toBeDisabled();
    expect(passkeyMock.start).toHaveBeenCalledTimes(1);
  });

  it('offers optional enrollment only when the authenticated server session supports it', async () => {
    passkeyMock.available = true;
    passkeyMock.start.mockRejectedValue(new Error('Please sign in again'));
    render(<ProfilePage />);
    fireEvent.click(screen.getByRole('button', { name: 'Create a passkey' }));
    await waitFor(() => expect(screen.getByText('Please sign in again')).toBeInTheDocument());
    expect(passkeyMock.start).toHaveBeenCalledWith(window.location.pathname);
    expect(screen.getByRole('button', { name: 'Create a passkey' })).toBeEnabled();
  });
  it('surfaces the shared organizations hub and canonical discovery routes', () => {
    render(<ProfilePage />);
    expect(screen.queryByTestId('profile-passkey-enrollment')).not.toBeInTheDocument();

    const membershipSection = screen.getByTestId('profile-organization-membership-section');

    expect(membershipSection).toBeInTheDocument();
    expect(within(membershipSection).getByText('Organization Memberships')).toBeInTheDocument();
    expect(within(membershipSection).getByText('Marty Org')).toBeInTheDocument();
    expect(within(membershipSection).getByText('Open Federation')).toBeInTheDocument();

    expect(within(membershipSection).getByRole('link', { name: 'View My Organizations' })).toHaveAttribute('href', '/console/organizations');
    expect(within(membershipSection).getByRole('link', { name: 'Discover More Organizations' })).toHaveAttribute('href', '/console/organizations/discover');
    expect(within(membershipSection).getByRole('link', { name: 'Use Join Code' })).toHaveAttribute('href', '/console/organizations/join');
  });
});
