import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router';
import { renderWithoutRouter, screen } from '@test/utils';

import AuthenticatedLayout from '../layouts/AuthenticatedLayout';

const { mockUseAuth } = vi.hoisted(() => ({
  mockUseAuth: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('../navigation', () => ({
  SidebarNavigation: () => <nav data-testid="sidebar-navigation" />,
}));

vi.mock('../navigation/ConsoleHeaderBar', () => ({
  ConsoleHeaderBar: () => <header data-testid="console-header" />,
}));

describe('AuthenticatedLayout credential-login outcome', () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      isAdministrator: false,
      isVendor: false,
      isApplicant: true,
      user: { email: 'member@example.test' },
    });
  });

  it('shows a durable passwordless sign-in receipt after credential login', () => {
    renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/applicant/catalog?auth_method=credential']}>
        <AuthenticatedLayout>
          <div>Catalog content</div>
        </AuthenticatedLayout>
      </MemoryRouter>,
    );

    const receipt = screen.getByTestId('credential-login-success');
    expect(receipt).toHaveTextContent('Signed in with Membership Badge');
    expect(receipt).toHaveTextContent('without entering another password');
    expect(receipt).toHaveTextContent('member@example.test');
  });

  it('does not show the receipt for ordinary authenticated navigation', () => {
    renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/applicant/catalog']}>
        <AuthenticatedLayout>
          <div>Catalog content</div>
        </AuthenticatedLayout>
      </MemoryRouter>,
    );

    expect(screen.queryByTestId('credential-login-success')).not.toBeInTheDocument();
  });

  it('does not treat a credential query marker as proof of an authenticated session', () => {
    mockUseAuth.mockReturnValue({
      isAdministrator: false,
      isVendor: false,
      isApplicant: false,
      user: null,
    });

    renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/applicant/catalog?auth_method=credential']}>
        <AuthenticatedLayout>
          <div>Catalog content</div>
        </AuthenticatedLayout>
      </MemoryRouter>,
    );

    expect(screen.queryByTestId('credential-login-success')).not.toBeInTheDocument();
  });
});
