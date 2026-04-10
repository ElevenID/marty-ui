import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderWithRouter, screen, waitFor, within } from '@test/utils'
import TeamPage from './TeamPage'

const {
  mockUseAuth,
  mockUseConsole,
  mockShowNotification,
  mockHasPermission,
  mockCan,
  mockRefreshPermissions,
  mockListMembers,
  mockListInvites,
  mockInviteMember,
  mockResendInvite,
  mockRevokeInvite,
  mockRemoveMember,
  mockUpdateMemberRole,
  mockListRoles,
  mockSetMemberRoles,
} = vi.hoisted(() => ({
  mockUseAuth: vi.fn(),
  mockUseConsole: vi.fn(),
  mockShowNotification: vi.fn(),
  mockHasPermission: vi.fn(),
  mockCan: vi.fn(),
  mockRefreshPermissions: vi.fn(),
  mockListMembers: vi.fn(),
  mockListInvites: vi.fn(),
  mockInviteMember: vi.fn(),
  mockResendInvite: vi.fn(),
  mockRevokeInvite: vi.fn(),
  mockRemoveMember: vi.fn(),
  mockUpdateMemberRole: vi.fn(),
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
    listInvites: (...args: unknown[]) => mockListInvites(...args),
    inviteMember: (...args: unknown[]) => mockInviteMember(...args),
    resendInvite: (...args: unknown[]) => mockResendInvite(...args),
    revokeInvite: (...args: unknown[]) => mockRevokeInvite(...args),
    updateMemberRole: (...args: unknown[]) => mockUpdateMemberRole(...args),
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
    hasPermission: mockHasPermission,
    can: mockCan,
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
    mockCan.mockReturnValue(true)
    mockRefreshPermissions.mockResolvedValue(undefined)
    mockListMembers.mockResolvedValue([
      {
        id: 'member_1',
        name: 'Alex Admin',
        email: 'alex@example.com',
        role: 'admin',
        joined_at: '2026-04-01T00:00:00Z',
      },
    ])
    mockListInvites.mockResolvedValue([
      {
        id: 'invite_1',
        email: 'pending@example.com',
        role: 'developer',
        created_at: '2026-04-01T00:00:00Z',
        expires_at: '2026-04-08T00:00:00Z',
      },
    ])
    mockInviteMember.mockResolvedValue({ id: 'invite_2' })
    mockResendInvite.mockResolvedValue({ id: 'invite_1', resent: true })
    mockRevokeInvite.mockResolvedValue({ ok: true })
    mockRemoveMember.mockResolvedValue({ ok: true })
    mockUpdateMemberRole.mockResolvedValue({ id: 'member_1', role: 'viewer' })
    mockListRoles.mockResolvedValue({
      roles: [
        {
          id: 'role_viewer',
          name: 'viewer',
          display_name: 'Viewer',
          description: 'Read-only access',
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
      expect(mockListInvites).toHaveBeenCalledWith('console-org')
    })

    await user.click(screen.getByRole('button', { name: 'org.team.members.actions.invite' }))
    await user.type(
      screen.getByLabelText('org.team.dialog.invite.emailLabel'),
      'new.member@example.com'
    )
    await user.click(screen.getByRole('button', { name: 'org.team.dialog.invite.send' }))

    await waitFor(() => {
      expect(mockInviteMember).toHaveBeenCalledWith('console-org', {
        email: 'new.member@example.com',
        role: 'developer',
      })
    })
  })

  it('uses the active console organization when changing roles', async () => {
    const { user } = renderWithRouter(<TeamPage />, {
      initialEntries: ['/console/org/team'],
    })

    await waitFor(() => {
      expect(screen.getByText('alex@example.com')).toBeInTheDocument()
    })

    const memberRow = screen.getByText('alex@example.com').closest('tr')
    expect(memberRow).not.toBeNull()

    await user.click(within(memberRow as HTMLElement).getByRole('button'))
    await user.click(screen.getByText('org.team.members.actions.changeRole'))
    await user.click(screen.getByText('Viewer'))
    await user.click(screen.getByRole('button', { name: 'org.team.dialog.changeRole.update' }))

    await waitFor(() => {
      expect(mockSetMemberRoles).toHaveBeenCalledWith('console-org', 'member_1', ['role_viewer'])
    })
  })
})