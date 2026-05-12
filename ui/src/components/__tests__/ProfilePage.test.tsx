import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';
import { within } from '@testing-library/react';

import ProfilePage from '../ProfilePage';

const mockSetActiveOrganizationId = vi.fn();
const mockSetActiveOrgId = vi.fn();
const mockRefreshUser = vi.fn();

vi.mock('../../services/authApi', () => ({
  updateProfilePicture: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      id: 'user-1',
      email: 'applicant@example.com',
      name: 'Ada Lovelace',
      applicant_id: 'app-1',
      roles: ['applicant'],
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
  it('surfaces the shared organizations hub and canonical discovery routes', () => {
    render(<ProfilePage />);

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