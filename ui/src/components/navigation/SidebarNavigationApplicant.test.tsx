import { describe, it, expect, vi, beforeEach } from 'vitest';
import { http, HttpResponse } from 'msw';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { renderWithoutRouter, screen, waitFor } from '../../test/utils';
import { server } from '../../test/mocks/server';
import SidebarNavigation from './SidebarNavigation';

const {
  mockCan,
  mockSetMode,
  mockUseMediaQuery,
  mockLogout,
} = vi.hoisted(() => ({
  mockCan: vi.fn(),
  mockSetMode: vi.fn(),
  mockUseMediaQuery: vi.fn(),
  mockLogout: vi.fn(),
}));

vi.mock('@mui/material', async () => {
  const actual = await vi.importActual<typeof import('@mui/material')>('@mui/material');
  return {
    ...actual,
    useMediaQuery: (...args: unknown[]) => mockUseMediaQuery(...args),
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    isAdministrator: false,
    isVendor: false,
    isApplicant: true,
    organizationId: 'org-123',
    logout: mockLogout,
  }),
}));

vi.mock('../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    can: mockCan,
  }),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    mode: 'applicant',
    setMode: mockSetMode,
    activeOrgId: 'org-123',
    memberships: [{ id: 'org-123', name: 'Acme Transit' }],
    isOrgConsoleAvailable: true,
    isApplicantConsoleAvailable: true,
    isOrgBlocked: false,
  }),
}));

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname}</div>;
}

describe('SidebarNavigation applicant organizations link', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    mockCan.mockReturnValue(true);
    mockUseMediaQuery.mockReturnValue(false);
    server.use(http.get('*/v1/organizations/:organizationId/dashboard/applicant-stats', () => (
      HttpResponse.json({ pending: 0, approved: 0, issuable: 0, total: 0 })
    )));
  });

  it.each([
    '/console/applicant/catalog',
    '/console/applicant/identity',
    '/console/applicant/dashboard',
  ])('does not request reviewer-only statistics from applicant navigation at %s', async (path) => {
    // Keep the real dashboard service and API client: an applicant would receive
    // this gateway denial if navigation tried to load organization review data.
    server.use(http.get('*/v1/organizations/:organizationId/dashboard/applicant-stats', () => (
      HttpResponse.json({
        error: 'forbidden',
        error_description: 'Missing required permission: application:review',
      }, { status: 403 })
    )));
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    try {
      const { user } = renderWithoutRouter(
        <MemoryRouter initialEntries={[path]}>
          <SidebarNavigation mobileOpen={false} onMobileClose={vi.fn()} />
          <LocationProbe />
        </MemoryRouter>,
      );

      expect(screen.getByRole('button', { name: 'Catalog' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'My Identity' })).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Settings' }));
      await waitFor(() => {
        expect(screen.getByTestId('location')).toHaveTextContent('/console/applicant/settings');
      });
      expect(fetchSpy.mock.calls.map(([input]) => String(input))).not.toEqual(
        expect.arrayContaining([expect.stringContaining('/dashboard/applicant-stats')]),
      );
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('exposes the organizations hub in applicant navigation', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/applicant/settings']}>
        <SidebarNavigation mobileOpen={false} onMobileClose={vi.fn()} />
        <LocationProbe />
        <Routes>
          <Route path="/console/applicant/settings" element={<div>Applicant Settings</div>} />
          <Route path="/console/organizations" element={<div>Organizations Hub</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByRole('button', { name: 'Organizations' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Organizations' }));

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/organizations');
      expect(screen.getByText('Organizations Hub')).toBeInTheDocument();
    });
  });

  it('renders a single settings entry in the mobile drawer', async () => {
    mockUseMediaQuery.mockReturnValue(true);

    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/applicant/catalog']}>
        <SidebarNavigation mobileOpen onMobileClose={vi.fn()} />
        <LocationProbe />
        <Routes>
          <Route path="/console/applicant/catalog" element={<div>Applicant Catalog</div>} />
          <Route path="/console/applicant/settings" element={<div>Applicant Settings</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getAllByRole('button', { name: 'Settings' })).toHaveLength(1);

    await user.click(screen.getByRole('button', { name: 'Settings' }));

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/applicant/settings');
      expect(screen.getByText('Applicant Settings')).toBeInTheDocument();
    });
  });
});
