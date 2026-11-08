import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';
import { within } from '@testing-library/react';

import ProfilePage from '../ProfilePage';
import { formatOfficialReference } from '../../utils/officialReferences';

const mockSetActiveOrganizationId = vi.fn();
const mockSetActiveOrgId = vi.fn();
const mockRefreshUser = vi.fn();

function createAuthState() {
  return {
    user: {
      user_id: 'native-account-1',
      email: 'applicant@example.com',
      username: 'ux-crawl',
      given_name: 'UX',
      family_name: 'Crawl',
      applicant_id: 'app-1',
      roles: ['applicant'],
    } as Record<string, unknown> | null,
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
  };
}

let mockAuthState = createAuthState();

vi.mock('../../services/authApi', () => ({
  updateProfilePicture: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockAuthState,
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: 'org-1',
    setActiveOrgId: mockSetActiveOrgId,
  }),
}));

describe('ProfilePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthState = createAuthState();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('applies the profile and membership layout without leaking obsolete DOM props', () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warnings = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { container } = render(<ProfilePage />);

    expect(container.querySelector('[item], [xs], [md], [flexwrap], [justifycontent], [fontfamily], [fontweight]')).toBeNull();
    const membershipSection = screen.getByTestId('profile-organization-membership-section');
    const roleStack = within(membershipSection).getByText('Administrator').closest('.MuiStack-root');
    const actionStack = within(membershipSection).getByRole('link', { name: 'Use Join Code' }).parentElement;
    expect(roleStack).toHaveStyle({ flexWrap: 'wrap' });
    expect(actionStack).toHaveStyle({ justifyContent: 'flex-start' });
    const messages = [...errors.mock.calls, ...warnings.mock.calls].map((call) => call.join(' '));
    expect(messages.filter((message) => /non-boolean|does not recognize|Grid.*(?:removed|deprecated)/i.test(message))).toEqual([]);
  });

  it('shows the native account name and reference from the current auth response', () => {
    render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'UX Crawl' })).toBeVisible();
    expect(within(screen.getByText('Full Name').closest('li')!).getByText('UX Crawl')).toBeVisible();
    expect(within(screen.getByText('Account Reference').closest('li')!).getByText(
      formatOfficialReference('native-account-1', 'account'),
    )).toBeVisible();
    expect(within(screen.getByText('Applicant Reference').closest('li')!).getByText(
      formatOfficialReference('app-1', 'applicant'),
    )).toBeVisible();
  });

  it.each([
    [{ given_name: '  Ada ', family_name: ' Lovelace  ' }, 'Ada Lovelace'],
    [{ given_name: 'Ada', family_name: null }, 'Ada'],
    [{ given_name: null, family_name: 'Lovelace' }, 'Lovelace'],
  ])('formats available native name claims without showing missing-data text', (claims, expected) => {
    mockAuthState.user = { ...mockAuthState.user, ...claims };
    render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: expected })).toBeVisible();
    expect(within(screen.getByText('Full Name').closest('li')!).getByText(expected)).toBeVisible();
  });

  it('keeps legacy name and identity fallbacks while preferring the native account ID', () => {
    mockAuthState.user = { ...mockAuthState.user, name: 'Legacy Display Name', id: 'legacy-id', subject: 'legacy-subject' };
    const { rerender } = render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'Legacy Display Name' })).toBeVisible();
    expect(within(screen.getByText('Account Reference').closest('li')!).getByText(
      formatOfficialReference('native-account-1', 'account'),
    )).toBeVisible();

    mockAuthState.user = { name: 'Legacy Account', id: 'legacy-id', email: 'legacy@example.com' };
    rerender(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'Legacy Account' })).toBeVisible();
    expect(within(screen.getByText('Account Reference').closest('li')!).getByText(
      formatOfficialReference('legacy-id', 'account'),
    )).toBeVisible();
  });

  it('uses the username for a nameless account heading without presenting it as a full name', () => {
    mockAuthState.user = { ...mockAuthState.user, given_name: ' ', family_name: null };
    render(<ProfilePage />);

    expect(screen.getByRole('heading', { name: 'ux-crawl' })).toBeVisible();
    expect(within(screen.getByText('Full Name').closest('li')!).getByText('Not provided')).toBeVisible();
  });

  it('centers the membership empty-state actions through CSS', () => {
    mockAuthState.organizations = [];
    render(<ProfilePage />);

    const actions = screen.getByRole('link', { name: 'Discover Organizations' }).parentElement;
    expect(actions).toHaveStyle({ justifyContent: 'center' });
    expect(actions).not.toHaveAttribute('justifyContent');
  });

  it('centers the loading state through CSS without layout DOM attributes', () => {
    mockAuthState.user = null;
    render(<ProfilePage />);

    const loadingState = screen.getByRole('progressbar').parentElement;
    expect(loadingState).toHaveStyle({ display: 'flex', alignItems: 'center', justifyContent: 'center' });
    for (const attribute of ['display', 'alignItems', 'justifyContent', 'minHeight']) {
      expect(loadingState).not.toHaveAttribute(attribute);
    }
  });

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
