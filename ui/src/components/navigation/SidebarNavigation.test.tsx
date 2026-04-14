import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { renderWithoutRouter, screen, waitFor } from '../../test/utils'
import SidebarNavigation from './SidebarNavigation'

const {
  mockCan,
  mockSetMode,
  mockGetApplicantStats,
} = vi.hoisted(() => ({
  mockCan: vi.fn(),
  mockSetMode: vi.fn(),
  mockGetApplicantStats: vi.fn(),
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    isAdministrator: false,
    isVendor: true,
    isApplicant: false,
    organizationId: 'org-123',
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
        <Route path="/console/org/team" element={<div>Team Page</div>} />
        <Route path="/console/org/notifications" element={<div>Notifications Page</div>} />
        <Route path="/console/org/deploy/signing-keys" element={<div>Signing Keys Page</div>} />
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
  })

  it('navigates to the key org console readiness routes', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org']}>
        <NavigationHarness />
      </MemoryRouter>
    )

    expect(screen.getByText('Dashboard Page')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Org' }))
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
    await user.click(screen.getByRole('link', { name: 'Signing Keys' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/deploy/signing-keys')
      expect(screen.getByText('Signing Keys Page')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Audit' }))

    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent('/console/org/audit')
      expect(screen.getByText('Audit Page')).toBeInTheDocument()
    })
  })
})