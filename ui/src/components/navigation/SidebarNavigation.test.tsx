import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { renderWithoutRouter, screen, waitFor } from '../../test/utils'
import SidebarNavigation from './SidebarNavigation'

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
}))

vi.mock('@mui/material', async () => {
  const actual = await vi.importActual<typeof import('@mui/material')>('@mui/material')
  return {
    ...actual,
    useMediaQuery: (...args: unknown[]) => mockUseMediaQuery(...args),
  }
})

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    isAdministrator: false,
    isVendor: true,
    isApplicant: false,
    organizationId: 'org-123',
    logout: mockLogout,
  }),
}))

vi.mock('../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    can: mockCan,
  }),
}))

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    mode: 'org',
    setMode: mockSetMode,
    activeOrgId: 'org-123',
    memberships: [{ id: 'org-123', name: 'Acme Transit' }],
    isOrgConsoleAvailable: true,
    isApplicantConsoleAvailable: false,
    isOrgBlocked: false,
  }),
}))

vi.mock('../../services/dashboardApi', () => ({
  getApplicantStats: (...args: unknown[]) => mockGetApplicantStats(...args),
}))

function LocationProbe() {
  const location = useLocation()

  return <div data-testid="location">{location.pathname}</div>
}

function NavigationHarness() {
  return (
    <>
      <SidebarNavigation mobileOpen={false} onMobileClose={vi.fn()} />
      <LocationProbe />
      <Routes>
        <Route path="/console/org" element={<div>Dashboard Page</div>} />
        <Route path="/console/org/deploy" element={<div>Deploy Page</div>} />
        <Route path="/console/org/deploy/key-management" element={<div>Key Management Page</div>} />
        <Route path="/console/org/trust/profiles/new" element={<div>New Trust Profile Page</div>} />
        <Route path="/console/organizations" element={<div>My Organizations Page</div>} />
        <Route path="/console/org/team" element={<div>Team Page</div>} />
        <Route path="/console/org/notifications" element={<div>Notifications Page</div>} />
        <Route path="/console/org/audit" element={<div>Audit Page</div>} />
      </Routes>
    </>
  )
}

describe('SidebarNavigation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.localStorage.clear()
    mockCan.mockReturnValue(true)
    mockGetApplicantStats.mockResolvedValue({ pending: 0 })
    mockUseMediaQuery.mockReturnValue(false)
  })

  it('navigates to the key org console readiness routes', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org']}>
        <NavigationHarness />
      </MemoryRouter>
    )

    expect(screen.getByText('Dashboard Page')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Org' }))
    await user.click(screen.getByRole('link', { name: 'My Organizations' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/organizations')
      expect(screen.getByText('My Organizations Page')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('link', { name: 'Team' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/team')
      expect(screen.getByText('Team Page')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('link', { name: 'Notifications' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/notifications')
      expect(screen.getByText('Notifications Page')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Deploy' }))
    await user.click(screen.getByRole('link', { name: 'Key Management' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/deploy/key-management')
      expect(screen.getByText('Key Management Page')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Audit' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/audit')
      expect(screen.getByText('Audit Page')).toBeInTheDocument()
    })
  })

  it('navigates parent sections in collapsed icon mode', async () => {
    window.localStorage.setItem('sidebar-collapsed', 'true')

    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/team']}>
        <NavigationHarness />
      </MemoryRouter>
    )

    await user.click(screen.getByRole('button', { name: 'Deploy' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/deploy')
      expect(screen.getByText('Deploy Page')).toBeInTheDocument()
    })
  })

  it('marks Trust Profiles active on the trust profile wizard route', async () => {
    renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/trust/profiles/new']}>
        <NavigationHarness />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('New Trust Profile Page')).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Trust Profiles' })).toHaveAttribute('aria-current', 'page')
    })
  })

  it('offsets the mobile drawer below the fixed header', async () => {
    mockUseMediaQuery.mockReturnValue(true)

    renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org']}>
        <SidebarNavigation mobileOpen onMobileClose={vi.fn()} />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(document.querySelector('.MuiDrawer-paper')).toBeTruthy()
    })

    expect(document.querySelector('.MuiDrawer-paper')).toHaveStyle({
      top: '64px',
      height: 'calc(100% - 64px)',
    })
  })

  it('keeps sign out in the mobile drawer without a duplicate settings shortcut', async () => {
    mockUseMediaQuery.mockReturnValue(true)

    const onMobileClose = vi.fn()
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org']}>
        <SidebarNavigation mobileOpen onMobileClose={onMobileClose} />
      </MemoryRouter>
    )

    expect(screen.queryByRole('link', { name: 'Settings' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    expect(onMobileClose).toHaveBeenCalledTimes(1)
    expect(mockLogout).toHaveBeenCalledTimes(1)
  })
})