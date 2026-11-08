import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { renderWithRouter, screen } from '@test/utils';

import OrganizationMembershipHub from './OrganizationMembershipHub';
import CreateOrganizationPage from './CreateOrganizationPage';

const { mockCreateOrganization } = vi.hoisted(() => ({
  mockCreateOrganization: vi.fn(),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    membershipLoadError: null,
    isOrgBootstrapRequired: false,
    isLoading: false,
  }),
}));

vi.mock('../../services/organizationsApi', () => ({
  createOrganization: mockCreateOrganization,
  getErrorMessage: (error: Error) => error.message,
}));

const existingOrganizations = [{
  id: 'existing-org',
  display_name: 'Existing Organization',
  membership: { roles: [{ name: 'owner' }], status: 'active', has_org_console_access: true },
}];

function renderHub(organizations: typeof existingOrganizations) {
  return renderWithRouter(
    <Routes>
      <Route
        path="/console/organizations"
        element={(
          <OrganizationMembershipHub
            organizations={organizations}
            managePath="/console/organizations"
            discoverPath="/console/organizations/discover"
            joinPath="/console/organizations/join"
          />
        )}
      />
      <Route path="/console/organizations/create" element={<CreateOrganizationPage />} />
    </Routes>,
    { initialEntries: ['/console/organizations'] },
  );
}

describe('OrganizationMembershipHub creation access', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    delete (window as any).__MARTY_RUNTIME_CONFIG__;
  });

  it.each([
    ['without memberships', []],
    ['with memberships', existingOrganizations],
  ] as const)('opens the enabled creation form %s', async (_description, organizations) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: true };
    const { user } = renderHub([...organizations]);

    await user.click(screen.getByRole('link', { name: 'Create Organization' }));

    expect(screen.getByRole('heading', { name: 'Create an Organization' })).toBeVisible();
    expect(screen.getByLabelText('Organization Slug')).toBeVisible();
    expect(screen.getByLabelText('Display Name')).toBeVisible();
    expect(mockCreateOrganization).not.toHaveBeenCalled();
  });

  it.each([
    ['without memberships', []],
    ['with memberships', existingOrganizations],
  ] as const)('hides creation when disabled %s, while preserving discovery and join access', (_description, organizations) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: false };
    renderHub([...organizations]);

    expect(screen.queryByRole('link', { name: 'Create Organization' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Discover.*Organizations/ })).toHaveAttribute('href', '/console/organizations/discover');
    expect(screen.getByRole('link', { name: 'Use Join Code' })).toHaveAttribute('href', '/console/organizations/join');
    expect(mockCreateOrganization).not.toHaveBeenCalled();
  });
});
