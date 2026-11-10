import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useState } from 'react'
import { MemoryRouter } from 'react-router'
import { renderWithoutRouter, screen, waitFor, within } from '../../test/utils'
import SidebarNavigation from './SidebarNavigation'
import {
  ConsoleHeaderBar,
  getAccountAvatarInitial,
  getAccountMenuDisplayName,
} from './ConsoleHeaderBar'

const {
  mockNavigate,
  mockUseMediaQuery,
  mockSetActiveOrgId,
  mockSetMode,
  mockLogout,
  mockSetActiveOrganizationId,
  mockAuthState,
  mockConsoleState,
  mockBrandingState,
  mockNotificationPermission,
  mockCan,
  mockGetUnreadCount,
  mockListNotifications,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockUseMediaQuery: vi.fn(),
  mockSetActiveOrgId: vi.fn().mockResolvedValue(undefined),
  mockSetMode: vi.fn(),
  mockLogout: vi.fn(),
  mockSetActiveOrganizationId: vi.fn(),
  mockNotificationPermission: { isLoading: false },
  mockCan: vi.fn(),
  mockGetUnreadCount: vi.fn(),
  mockListNotifications: vi.fn(),
  mockAuthState: {
    user: {
      sub: 'user-123',
      given_name: 'Maree',
      email: 'maree@example.com',
      picture: null,
      organizations: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
    },
    logout: vi.fn(),
    organizationId: 'org-123',
    organizationName: 'Marty Org',
    organizations: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
    setActiveOrganizationId: vi.fn(),
    isAdministrator: false,
    isVendor: true,
    isApplicant: false,
  },
  mockConsoleState: {
    mode: 'org',
    activeOrgId: 'org-123',
    memberships: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
    isOrgBlocked: false,
    setActiveOrgId: vi.fn().mockResolvedValue(undefined),
    setMode: vi.fn(),
    isApplicantConsoleAvailable: true,
    isOrgConsoleAvailable: true,
  },
  mockBrandingState: {
    appName: 'ElevenID LLC',
    shortName: 'ElevenID',
    logoUrl: null,
  },
}))

vi.mock('@mui/material', async () => {
  const actual = await vi.importActual<typeof import('@mui/material')>('@mui/material')
  return {
    ...actual,
    useMediaQuery: (...args: unknown[]) => mockUseMediaQuery(...args),
  }
})

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    ...mockAuthState,
    logout: mockLogout,
    setActiveOrganizationId: mockSetActiveOrganizationId,
  }),
}))

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    ...mockConsoleState,
    setActiveOrgId: mockSetActiveOrgId,
    setMode: mockSetMode,
  }),
}))

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => ({
    branding: mockBrandingState,
    isLoading: false,
  }),
}))

vi.mock('../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...mockNotificationPermission, can: mockCan }),
}))

vi.mock('../../services/notificationsApi', () => ({
  default: {
    getUnreadCount: (...args: unknown[]) => mockGetUnreadCount(...args),
    listNotifications: (...args: unknown[]) => mockListNotifications(...args),
  },
}))

vi.mock('../../application/session/authSession', async () => {
  const actual = await vi.importActual<typeof import('../../application/session/authSession')>('../../application/session/authSession')
  return actual
})

function setViewportWidth(width: number) {
  mockUseMediaQuery.mockImplementation((query: string) => {
    const maximum = query.match(/max-width:\s*([\d.]+)px/)?.[1]
    return maximum !== undefined && width <= Number(maximum)
  })
}

function MobileNavigationHarness() {
  const [open, setOpen] = useState(false)
  return <>
    <ConsoleHeaderBar onMobileMenuToggle={() => setOpen(true)} />
    <SidebarNavigation mobileOpen={open} onMobileClose={() => setOpen(false)} />
  </>
}

describe('ConsoleHeaderBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setViewportWidth(390)
    window.localStorage.removeItem('sidebar-collapsed')
    mockNotificationPermission.isLoading = false
    mockCan.mockReturnValue(false)
    mockGetUnreadCount.mockReset().mockResolvedValue({ count: 3 })
    mockListNotifications.mockReset().mockImplementation(async ({ organization_id }: { organization_id: string }) => [{
      id: `notification-${organization_id}`,
      organization_id,
      title: `Notification for ${organization_id}`,
      body: 'A credential is ready.',
      created_at: '2026-11-10T00:00:00Z',
      read: false,
    }])
    Object.assign(mockBrandingState, {
      appName: 'ElevenID LLC',
      shortName: 'ElevenID',
      logoUrl: null,
    })
    Object.assign(mockAuthState, {
      user: {
        sub: 'user-123',
        given_name: 'Maree',
        email: 'maree@example.com',
        picture: null,
        organizations: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
      },
      organizationId: 'org-123',
      organizationName: 'Marty Org',
      organizations: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
      isAdministrator: false,
      isVendor: true,
      isApplicant: false,
    })
    Object.assign(mockConsoleState, {
      mode: 'org',
      activeOrgId: 'org-123',
      memberships: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
      isOrgBlocked: false,
      isApplicantConsoleAvailable: true,
      isOrgConsoleAvailable: true,
    })
  })

  it.each([390, 1280])('mounts the scoped notification bell and opens its inbox at %spx', async (width) => {
    setViewportWidth(width)
    mockCan.mockImplementation((resource, action) => resource === 'notification' && action === 'view')
    const { user } = renderWithoutRouter(
      <MemoryRouter><ConsoleHeaderBar onMobileMenuToggle={vi.fn()} /></MemoryRouter>
    )
    const header = screen.getByRole('banner')
    const bell = within(header).getByRole('button', { name: 'notifications' })
    await waitFor(() => expect(within(bell).getByText('3')).toBeInTheDocument())
    expect(mockGetUnreadCount).toHaveBeenCalledWith('org-123', 'user-123')
    expect(within(header).getByTestId('language-switcher')).toBeVisible()
    expect(within(header).getByTestId('console-account-menu-button')).toBeVisible()
    if (width < 900) {
      expect(within(header).getByRole('button', { name: 'MO' })).toBeVisible()
      expect(within(header).getByRole('button', { name: 'open drawer' })).toBeVisible()
    }
    await user.click(bell)
    expect(await screen.findByText('Notification for org-123')).toBeVisible()
    expect(mockListNotifications).toHaveBeenCalledWith({ organization_id: 'org-123', recipient_id: 'user-123', limit: 10 })
    expect(screen.getByRole('link', { name: 'View All Notifications' })).toHaveAttribute('href', '/console/org/notifications')
  })

  it.each([
    { width: 320, collapsed: false },
    { width: 390, collapsed: false },
    { width: 320, collapsed: true },
  ])('keeps narrow header controls and both console modes reachable at $width px with collapsed=$collapsed', async ({ width, collapsed }) => {
    setViewportWidth(width)
    window.localStorage.setItem('sidebar-collapsed', String(collapsed))
    mockCan.mockImplementation((resource, action) => resource === 'notification' && action === 'view')
    const { user, rerender } = renderWithoutRouter(
      <MemoryRouter><MobileNavigationHarness /></MemoryRouter>
    )
    const header = screen.getByRole('banner')
    expect(within(header).queryByRole('button', { name: 'Me' })).not.toBeInTheDocument()
    expect(within(header).queryByRole('button', { name: 'Org' })).not.toBeInTheDocument()
    if (width < 380) expect(within(header).queryByAltText('ElevenID LLC')).not.toBeInTheDocument()
    else expect(within(header).getByAltText('ElevenID LLC')).toBeVisible()
    expect(within(header).getByTestId('language-switcher')).toBeVisible()
    expect(within(header).getByRole('button', { name: 'MO' })).toBeVisible()
    expect(within(header).getByTestId('console-account-menu-button')).toBeVisible()
    const bell = within(header).getByRole('button', { name: 'notifications' })
    await waitFor(() => expect(within(bell).getByText('3')).toBeInTheDocument())
    const drawerButton = within(header).getByRole('button', { name: 'open drawer' })
    expect(drawerButton).toHaveStyle({ marginLeft: '0px' })
    await user.click(drawerButton)
    const modeSwitcher = within(screen.getByRole('group'))
    expect(modeSwitcher.getByRole('button', { name: 'Applicant' })).toBeVisible()
    expect(modeSwitcher.getByRole('button', { name: 'Org' })).toBeVisible()
    await user.click(modeSwitcher.getByRole('button', { name: 'Applicant' }))
    await waitFor(() => expect(mockSetMode).toHaveBeenLastCalledWith('applicant'))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    mockConsoleState.mode = 'applicant'
    rerender(<MemoryRouter><MobileNavigationHarness /></MemoryRouter>)
    await user.click(within(screen.getByRole('banner')).getByRole('button', { name: 'open drawer' }))
    await user.click(within(screen.getByRole('group')).getByRole('button', { name: 'Org' }))
    await waitFor(() => expect(mockSetMode).toHaveBeenLastCalledWith('org'))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(window.localStorage.getItem('sidebar-collapsed')).toBe(String(collapsed))
  })

  it.each(['applicant mode', 'permissions loading', 'permission denied', 'no organization', 'no principal'])('does not render or poll the header bell with %s', (condition) => {
    mockCan.mockReturnValue(condition !== 'permission denied')
    if (condition === 'applicant mode') mockConsoleState.mode = 'applicant'
    if (condition === 'permissions loading') mockNotificationPermission.isLoading = true
    if (condition === 'no organization') mockConsoleState.activeOrgId = ''
    if (condition === 'no principal') mockAuthState.user.sub = ''
    renderWithoutRouter(
      <MemoryRouter><ConsoleHeaderBar onMobileMenuToggle={vi.fn()} /></MemoryRouter>
    )
    expect(screen.queryByRole('button', { name: 'notifications' })).not.toBeInTheDocument()
    expect(mockGetUnreadCount).not.toHaveBeenCalled()
    expect(mockListNotifications).not.toHaveBeenCalled()
  })

  it('resets the open notification inbox when the selected organization or console mode changes', async () => {
    mockCan.mockReturnValue(true)
    mockGetUnreadCount.mockImplementation(async (organizationId) => ({ count: organizationId === 'org-123' ? 3 : 7 }))
    const header = <MemoryRouter><ConsoleHeaderBar onMobileMenuToggle={vi.fn()} /></MemoryRouter>
    const { user, rerender } = renderWithoutRouter(header)
    await user.click(screen.getByRole('button', { name: 'notifications' }))
    expect(await screen.findByText('Notification for org-123')).toBeVisible()
    mockConsoleState.activeOrgId = 'org-456'
    rerender(<MemoryRouter><ConsoleHeaderBar onMobileMenuToggle={vi.fn()} /></MemoryRouter>)
    const bell = screen.getByRole('button', { name: 'notifications' })
    expect(bell).not.toHaveAttribute('aria-expanded', 'true')
    expect(screen.queryByText('Notification for org-123')).not.toBeInTheDocument()
    await waitFor(() => expect(within(bell).getByText('7')).toBeInTheDocument())
    expect(mockGetUnreadCount).toHaveBeenLastCalledWith('org-456', 'user-123')
    await user.click(bell)
    expect(await screen.findByText('Notification for org-456')).toBeVisible()
    expect(mockListNotifications).toHaveBeenLastCalledWith({ organization_id: 'org-456', recipient_id: 'user-123', limit: 10 })
    mockConsoleState.mode = 'applicant'
    rerender(<MemoryRouter><ConsoleHeaderBar onMobileMenuToggle={vi.fn()} /></MemoryRouter>)
    expect(screen.queryByRole('button', { name: 'notifications' })).not.toBeInTheDocument()
    expect(screen.queryByText('Notification for org-456')).not.toBeInTheDocument()
  })

  it('keeps logo-only branding and inline console switching on wider mobile headers', () => {
    setViewportWidth(768)
    renderWithoutRouter(
      <MemoryRouter>
        <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
      </MemoryRouter>
    )

    const meToggle = screen.getByRole('button', { name: 'Me' })
    const orgToggle = screen.getByRole('button', { name: 'Org' })

    expect(screen.getByAltText('ElevenID LLC')).toHaveAttribute('src', '/apple-touch-icon.png')
    expect(screen.queryByText('ElevenID LLC')).not.toBeInTheDocument()
    expect(meToggle.querySelector('svg')).toBeNull()
    expect(orgToggle.querySelector('svg')).toBeNull()
    expect(screen.getByRole('button', { name: 'MO' })).not.toBeDisabled()
    expect(screen.getByRole('button', { name: 'MO' })).toHaveTextContent('MO')
    expect(screen.getByTestId('language-switcher')).toHaveAttribute('data-compact', 'true')
    expect(screen.queryByRole('button', { name: 'Logout' })).not.toBeInTheDocument()
  })

  it('routes the account settings action to the org settings page in org mode', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
      </MemoryRouter>
    )

    await user.click(screen.getByTestId('console-account-menu-button'))

    expect(screen.getByText('Maree')).toBeInTheDocument()
    expect(screen.queryByText('Marty Org')).not.toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Settings' })).toHaveAttribute('href', '/console/org/settings')
  })

  it.each([
    { menu: 'organization', width: '280px', overflow: 'hidden', action: 'Search & Join Organizations' },
    { menu: 'account', width: '200px', overflow: 'visible', action: 'Settings' },
  ])('applies $menu menu paper styles without leaking props and closes on selection', async ({ menu, width, overflow, action }) => {
    const errorSpy = vi.spyOn(console, 'error')
    try {
      const { user } = renderWithoutRouter(
        <MemoryRouter>
          <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
        </MemoryRouter>
      )

      const trigger = menu === 'organization'
        ? screen.getByRole('button', { name: 'MO' })
        : screen.getByTestId('console-account-menu-button')
      await user.click(trigger)

      const paper = screen.getByRole('menu').closest('.MuiPaper-root')
      expect(paper).toHaveStyle({ minWidth: width, overflow })
      expect(paper).toHaveClass('MuiPaper-elevation0')
      expect(document.querySelector('[paperprops]')).toBeNull()
      expect(errorSpy.mock.calls.flat().join(' ')).not.toContain('PaperProps')

      await user.click(screen.getByRole('menuitem', { name: action }))
      await waitFor(() => expect(screen.queryByRole('menu')).not.toBeInTheDocument())
      if (menu === 'organization') {
        expect(mockNavigate).toHaveBeenCalledWith('/organizations/discover')
      }
    } finally {
      errorSpy.mockRestore()
    }
  })

  it.each([
    { mode: 'applicant', role: 'Reviewer', administrator: false, label: 'Applicant' },
    { mode: 'org', role: 'Reviewer', administrator: false, label: 'Reviewer' },
    { mode: 'org', role: null, administrator: false, label: 'Organization Console' },
    { mode: 'applicant', role: null, administrator: true, label: 'Administrator' },
  ])('labels the $mode account from its context and actual roles as $label', async ({ mode, role, administrator, label }) => {
    Object.assign(mockAuthState, {
      isAdministrator: administrator,
      isVendor: true,
      isApplicant: true,
    })
    Object.assign(mockConsoleState, {
      mode,
      memberships: [{
        id: 'org-123',
        display_name: 'Marty Org',
        membership: { roles: role ? [{ name: 'reviewer', display_name: role }] : [] },
      }],
    })

    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
      </MemoryRouter>
    )
    await user.click(screen.getByTestId('console-account-menu-button'))

    expect(screen.getByText(label)).toBeVisible()
    expect(screen.queryByText('Vendor')).not.toBeInTheDocument()
  })

  it('uses the Canvas learner name when the LTI username is opaque', () => {
    Object.assign(mockAuthState, {
      user: {
        user_id: 'canvas-lti-abc123',
        username: '06e74e0c-1858-4642-a834-ffa0b03acfcd',
        given_name: 'ElevenID Test',
        family_name: '',
        email: 'learner@example.edu',
        picture: null,
        roles: ['applicant', 'canvas_lti_learner'],
        organizations: [{ id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } }],
      },
      isVendor: false,
      isApplicant: true,
    })

    renderWithoutRouter(
      <MemoryRouter>
        <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
      </MemoryRouter>
    )

    const expectedDisplayName = 'ElevenID Test'
    expect(screen.getByLabelText(`Account menu for ${expectedDisplayName}`)).toBeInTheDocument()
    expect(getAccountMenuDisplayName(mockAuthState.user)).toBe(expectedDisplayName)
  })

  it('derives account menu labels for normal and Canvas sessions', () => {
    expect(getAccountMenuDisplayName({
      given_name: 'Maree',
      family_name: 'Smith',
      username: 'maree',
    })).toBe('Maree Smith')

    expect(getAccountMenuDisplayName({
      user_id: 'canvas-lti-abc123',
      username: 'canvas-user-1',
      given_name: 'ElevenID Test',
      roles: ['canvas_lti_learner'],
    })).toBe('canvas-user-1')

    expect(getAccountMenuDisplayName({
      user_id: 'canvas-lti-abc123',
      username: '06e74e0c-1858-4642-a834-ffa0b03acfcd',
      given_name: 'ElevenID',
      family_name: 'Test',
      email: 'learner@example.edu',
      roles: ['canvas_lti_learner'],
    })).toBe('ElevenID Test')

    expect(getAccountAvatarInitial({
      user_id: 'canvas-lti-abc123',
      username: '06e74e0c-1858-4642-a834-ffa0b03acfcd',
      given_name: 'ElevenID Test',
      roles: ['canvas_lti_learner'],
    })).toBe('E')
  })

  it('blocks organization switching until console memberships are loaded', async () => {
    Object.assign(mockAuthState, {
      organizationId: 'org-123',
      organizationName: 'Marty Org',
      organizations: [
        { id: 'org-123', display_name: 'Marty Org', membership: { roles: [] } },
        { id: 'org-applicant', display_name: 'Applicant Only Org', membership: { permissions: ['organization:view'] } },
      ],
    })
    mockAuthState.user = {
      ...mockAuthState.user,
      organizations: mockAuthState.organizations,
    }
    Object.assign(mockConsoleState, {
      mode: 'org',
      activeOrgId: null,
      memberships: [],
      isOrgConsoleAvailable: false,
      isApplicantConsoleAvailable: true,
    })

    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ConsoleHeaderBar onMobileMenuToggle={vi.fn()} />
      </MemoryRouter>
    )

    const orgButton = screen.getByRole('button', { name: 'MO' })
    expect(orgButton).toBeDisabled()
    expect(mockSetMode).not.toHaveBeenCalled()
    expect(mockSetActiveOrganizationId).not.toHaveBeenCalled()
    expect(mockNavigate).not.toHaveBeenCalled()
    expect(mockSetActiveOrgId).not.toHaveBeenCalled()
  })
})
