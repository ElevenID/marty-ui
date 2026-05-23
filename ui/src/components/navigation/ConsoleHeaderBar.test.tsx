import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { renderWithoutRouter, screen } from '../../test/utils'
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
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockUseMediaQuery: vi.fn(),
  mockSetActiveOrgId: vi.fn().mockResolvedValue(undefined),
  mockSetMode: vi.fn(),
  mockLogout: vi.fn(),
  mockSetActiveOrganizationId: vi.fn(),
  mockAuthState: {
    user: {
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

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
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

vi.mock('../../application/session/authSession', async () => {
  const actual = await vi.importActual<typeof import('../../application/session/authSession')>('../../application/session/authSession')
  return actual
})

describe('ConsoleHeaderBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseMediaQuery.mockReturnValue(true)
    Object.assign(mockBrandingState, {
      appName: 'ElevenID LLC',
      shortName: 'ElevenID',
      logoUrl: null,
    })
    Object.assign(mockAuthState, {
      user: {
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

  it('uses logo-only branding and compact selectors on mobile', () => {
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

  it('keeps the organization selector enabled from auth organizations when console memberships are empty', async () => {
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
    expect(orgButton).not.toBeDisabled()

    await user.click(orgButton)
    await user.click(screen.getByRole('menuitem', { name: 'Applicant Only Org' }))

    expect(mockSetMode).toHaveBeenCalledWith('applicant')
    expect(mockSetActiveOrganizationId).toHaveBeenCalledWith('org-applicant')
    expect(mockNavigate).toHaveBeenCalledWith('/console/applicant/catalog')
    expect(mockSetActiveOrgId).not.toHaveBeenCalledWith('org-applicant')
  })
})
