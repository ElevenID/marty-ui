import { describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { renderWithoutRouter, screen } from '@test/utils';

import PublicRoutes from './PublicRoutes';

const {
  mockUseAuth,
  mockGetPublicLoginFallback,
} = vi.hoisted(() => ({
  mockUseAuth: vi.fn(),
  mockGetPublicLoginFallback: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('@ui-public-routes', () => ({
  getPublicLoginFallback: (...args: unknown[]) => mockGetPublicLoginFallback(...args),
  renderPublicRoot: () => <div data-testid="public-root">Public root</div>,
  renderMarketingRoutes: () => null,
}));

vi.mock('../../components/ProtectedRoute', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  ApplicantRoute: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  VendorRoute: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('../../components/LoginPage', () => ({
  default: ({ fallbackRedirectTo = '/' }: { fallbackRedirectTo?: string }) => (
    <div data-testid="login-page" data-fallback-redirect={fallbackRedirectTo}>
      Login page
    </div>
  ),
}));

vi.mock('../../components/AuthCallback', () => ({
  default: () => <div data-testid="auth-callback">Auth callback</div>,
}));

vi.mock('../../components/WalletSetup', () => ({
  default: () => <div data-testid="wallet-setup">Wallet setup</div>,
}));

vi.mock('../../components/InviteAcceptPage', () => ({
  default: () => <div data-testid="invite-accept">Invite accept</div>,
}));

vi.mock('../../components/ApplyPage', () => ({
  default: () => <div data-testid="apply-page">Apply page</div>,
}));

vi.mock('../../components/ApiDocumentation', () => ({
  default: () => <div data-testid="api-docs">API docs</div>,
}));

vi.mock('../../components/pages/MyOrganizationsPage', () => ({
  default: () => <div data-testid="my-organizations">My organizations</div>,
}));

vi.mock('../../components/pages/DiscoverOrganizationsPage', () => ({
  default: () => <div data-testid="discover-organizations">Discover organizations</div>,
}));

vi.mock('../../components/pages/JoinOrganizationPage', () => ({
  default: () => <div data-testid="join-organization">Join organization</div>,
}));

vi.mock('../../components/pages/CanvasLtiExperiencePage', () => ({
  default: () => <div data-testid="canvas-lti-experience">Canvas LTI experience</div>,
}));

vi.mock('../../components/BrowserRedirect', () => ({
  default: ({ to, preserveSearch }: { to: string; preserveSearch?: boolean }) => (
    <div data-testid="browser-redirect" data-preserve-search={String(Boolean(preserveSearch))}>
      {to}
    </div>
  ),
}));

vi.mock('../../components/layouts', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    PublicLayout: () => (
      <div data-testid="public-layout">
        <actual.Outlet />
      </div>
    ),
  };
});

vi.mock('../../components/preview', () => ({
  PreviewLayout: () => <div data-testid="preview-layout">Preview layout</div>,
  PreviewCatalogPage: () => <div data-testid="preview-catalog">Preview catalog</div>,
  PreviewCredentialPage: () => <div data-testid="preview-credential">Preview credential</div>,
  PreviewApplicationPage: () => <div data-testid="preview-application">Preview application</div>,
  PreviewFlowPage: () => <div data-testid="preview-flow">Preview flow</div>,
}));

vi.mock('../../components/console', () => ({
  NotificationPreferencesPage: () => <div data-testid="notification-preferences">Notification preferences</div>,
}));

describe('PublicRoutes', () => {
  it('passes the variant login fallback to the login route', () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isAdministrator: false,
      isVendor: false,
      isApplicant: false,
      login: vi.fn(),
    });
    mockGetPublicLoginFallback.mockReturnValue('/');

    renderWithoutRouter(
      <MemoryRouter initialEntries={['/login']}>
        <PublicRoutes />
      </MemoryRouter>,
    );

    expect(screen.getByTestId('login-page')).toHaveAttribute('data-fallback-redirect', '/');
    expect(mockGetPublicLoginFallback).toHaveBeenCalledWith({
      isAuthenticated: false,
      isAdministrator: false,
      isVendor: false,
      isApplicant: false,
    });
  });

  it('renders Canvas LTI as an auth entry page outside the marketing layout', () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isAdministrator: false,
      isVendor: false,
      isApplicant: false,
      login: vi.fn(),
    });
    mockGetPublicLoginFallback.mockReturnValue('/');

    renderWithoutRouter(
      <MemoryRouter initialEntries={['/canvas/lti/experience?state=state-1']}>
        <PublicRoutes />
      </MemoryRouter>,
    );

    expect(screen.getByTestId('canvas-lti-experience')).toBeInTheDocument();
    expect(screen.queryByTestId('public-layout')).not.toBeInTheDocument();
  });

  it('falls through for unsupported public routes instead of redirecting', () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isAdministrator: false,
      isVendor: false,
      isApplicant: false,
      login: vi.fn(),
    });
    mockGetPublicLoginFallback.mockReturnValue('/');

    renderWithoutRouter(
      <MemoryRouter initialEntries={['/unsupported-public-route?external_credential_id=canvas-cred-1']}>
        <PublicRoutes />
      </MemoryRouter>,
    );

    expect(screen.queryByTestId('browser-redirect')).not.toBeInTheDocument();
    expect(screen.getByTestId('public-root')).toBeInTheDocument();
  });
});
