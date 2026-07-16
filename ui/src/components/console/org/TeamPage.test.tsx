import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor, within } from '@test/utils'
import TeamPage from './TeamPage'

const {
  mockUseAuth,
  mockUseConsole,
  mockShowNotification,
  mockHasPermission,
  mockRefreshPermissions,
  mockListMembers,
  mockInviteMember,
  mockRemoveMember,
  mockListRoles,
  mockSetMemberRoles,
} = vi.hoisted(() => ({
  mockUseAuth: vi.fn(),
  mockUseConsole: vi.fn(),
  mockShowNotification: vi.fn(),
  mockHasPermission: vi.fn(),
  mockRefreshPermissions: vi.fn(),
  mockListMembers: vi.fn(),
  mockInviteMember: vi.fn(),
  mockRemoveMember: vi.fn(),
  mockListRoles: vi.fn(),
  mockSetMemberRoles: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: { email?: string; count?: number }) => {
      if (options?.email) {
        return `${key}:${options.email}`
      }

      if (typeof options?.count === 'number') {
        return `${key}:${options.count}`
      }

      return key
    },
  }),
}))

vi.mock('../../../services/teamApi', () => ({
  default: {
    listMembers: (...args: unknown[]) => mockListMembers(...args),
    inviteMember: (...args: unknown[]) => mockInviteMember(...args),
    removeMember: (...args: unknown[]) => mockRemoveMember(...args),
  },
}))

vi.mock('../../../services/rbacApi', () => ({
  listRoles: (...args: unknown[]) => mockListRoles(...args),
  setMemberRoles: (...args: unknown[]) => mockSetMemberRoles(...args),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    can: mockHasPermission,
    hasPermission: mockHasPermission,
    refresh: mockRefreshPermissions,
    getPermissionMessage: () => '',
  }),
}))

describe('TeamPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('confirm', vi.fn(() => true))

    mockUseAuth.mockReturnValue({
      organizationId: 'auth-org',
      user: { id: 'user_1', email: 'owner@example.com' },
    })
    mockUseConsole.mockReturnValue({
      activeOrgId: 'console-org',
    })
    mockHasPermission.mockReturnValue(true)
    mockRefreshPermissions.mockResolvedValue(undefined)
    mockListMembers.mockResolvedValue([
      {
        id: 'member_1',
        user_id: 'user_2',
        email: 'alex@example.com',
        roles: [{ id: 'role_admin', name: 'admin', display_name: 'Admin' }],
        status: 'active',
        joined_at: '2026-04-01T00:00:00Z',
        is_owner: false,
      },
      {
        id: 'member_invite_1',
        email: 'pending@example.com',
        roles: [{ id: 'role_viewer', name: 'viewer', display_name: 'Viewer' }],
        status: 'invited',
        invited_at: '2026-04-01T00:00:00Z',
        is_owner: false,
      },
    ])
    mockInviteMember.mockResolvedValue({ id: 'invite_2' })
    mockRemoveMember.mockResolvedValue({ ok: true })
    mockListRoles.mockResolvedValue({
      roles: [
        {
          id: 'role_viewer',
          name: 'viewer',
          display_name: 'Viewer',
          description: 'Read-only access',
          is_system: true,
          is_default_for_new_members: true,
        },
        {
          id: 'role_operator',
          name: 'operator',
          display_name: 'Operator',
          description: 'Operational access',
          is_system: true,
        },
      ],
    })
    mockSetMemberRoles.mockResolvedValue({ ok: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('uses the active console organization when inviting a member', async () => {
    const { user } = renderWithRouter(<TeamPage />, {
      initialEntries: ['/console/org/team'],
    })

    await waitFor(() => {
      expect(mockListMembers).toHaveBeenCalledWith('console-org')
      expect(mockListRoles).toHaveBeenCalledWith('console-org')
    })

    await user.click(screen.getByRole('button', { name: 'org.team.members.actions.invite' }))
    await user.type(
      screen.getByLabelText('org.team.dialog.invite.emailLabel'),
      'new.member@example.com'
    )
    await user.click(screen.getByText('Operator'))
    await user.click(screen.getByRole('button', { name: 'org.team.dialog.invite.send' }))

    await waitFor(() => {
      expect(mockInviteMember).toHaveBeenCalledWith('console-org', {
        email: 'new.member@example.com',
        role_ids: ['role_viewer', 'role_operator'],
      })
    })
  })

  it('uses the active console organization when changing roles', async () => {
    const { user } = renderWithRouter(<TeamPage />, {
      initialEntries: ['/console/org/team'],
    })

    await waitFor(() => {
      expect(screen.getAllByText('alex@example.com').length).toBeGreaterThan(0)
    })

    const memberRow = screen.getAllByText('alex@example.com')[0].closest('tr')
    expect(memberRow).not.toBeNull()

    await user.click(within(memberRow as HTMLElement).getByRole('button'))
    await user.click(screen.getByText('org.team.members.actions.changeRole'))
    await user.click(screen.getByText('Operator'))
    await user.click(screen.getByRole('button', { name: 'org.team.dialog.changeRole.update' }))

    await waitFor(() => {
      expect(mockSetMemberRoles).toHaveBeenCalledWith('console-org', 'member_1', ['role_admin', 'role_operator'])
    })
  })

  it('release personas can view team state but cannot mutate it', async () => {
    mockHasPermission.mockImplementation((resource: string, action: string) => (
      resource === 'team' && action === 'view'
    ))

    renderWithRouter(<TeamPage />, {
      initialEntries: ['/console/org/team'],
    })

    await waitFor(() => {
      expect(screen.getAllByText('alex@example.com').length).toBeGreaterThan(0)
      expect(screen.getAllByText('pending@example.com').length).toBeGreaterThan(0)
    })

    expect(screen.queryByRole('button', { name: 'org.team.members.actions.invite' })).not.toBeInTheDocument()

    const memberRow = screen.getAllByText('alex@example.com')[0].closest('tr')
    expect(memberRow).not.toBeNull()
    expect(within(memberRow as HTMLElement).queryByRole('button')).not.toBeInTheDocument()

    const inviteRow = screen.getAllByText('pending@example.com')[0].closest('tr')
    expect(inviteRow).not.toBeNull()
    expect(within(inviteRow as HTMLElement).queryByRole('button')).not.toBeInTheDocument()
  })

  it('surfaces role loading failures instead of rendering team management with empty roles', async () => {
    mockListRoles.mockRejectedValue(new Error('Roles service unavailable'))

    renderWithRouter(<TeamPage />, {
      initialEntries: ['/console/org/team'],
    })

    expect((await screen.findAllByText(/Roles service unavailable/i)).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'org.team.members.actions.invite' })).toBeDisabled()
    expect(screen.queryByText('alex@example.com')).not.toBeInTheDocument()
  })
})
