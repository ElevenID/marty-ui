import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { renderWithoutRouter, screen, waitFor } from '../../test/utils';
import SidebarNavigation from './SidebarNavigation';

const {
  mockCan,
  mockSetMode,
  mockGetApplicantStats,
  mockUseMediaQuery,
  mockLogout,
} = vi.hoisted(() => ({
  mockCan: vi.fn(),
  mockSetMode: vi.fn(),
  mockGetApplicantStats: vi.fn(),
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

vi.mock('../../services/dashboardApi', () => ({
  getApplicantStats: (...args: unknown[]) => mockGetApplicantStats(...args),
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
    mockGetApplicantStats.mockResolvedValue({ pending: 0 });
    mockUseMediaQuery.mockReturnValue(false);
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