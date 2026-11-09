import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, renderWithRouter, screen, waitFor, within } from '@test/utils'
import { Route, Routes, useLocation } from 'react-router'
import TeamPage from './TeamPage'
import { TeamSnapshotPanel } from '../dashboard/TeamSnapshotPanel'

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
  mockPermissionInstance,
  permissionState,
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
  mockPermissionInstance: vi.fn(),
  permissionState: { isLoading: false },
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

vi.mock('../../../hooks/usePermissions', async () => {
  const { useState } = await import('react')
  return {
    usePermissions: () => {
      const [instance] = useState(() => mockPermissionInstance())
      return {
        can: instance.can || mockHasPermission,
        hasPermission: instance.can || mockHasPermission,
        refresh: mockRefreshPermissions,
        getPermissionMessage: () => '',
        isLoading: instance.isLoading,
      }
    },
  }
})

function CurrentLocation() {
  const location = useLocation()
  return <output data-testid="current-location">{location.pathname}{location.search}</output>
}

function TeamWithLocation() {
  return <><TeamPage /><CurrentLocation /></>
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

async function openRoleDialog(user: ReturnType<typeof renderWithRouter>['user'], email = 'alex@example.com') {
  const cells = await screen.findAllByText(email)
  const row = cells[0].closest('tr') as HTMLElement
  await user.click(within(row).getByRole('button'))
  await user.click(screen.getByText('org.team.members.actions.changeRole'))
  return await screen.findByRole('dialog')
}

async function startRemoval(user: ReturnType<typeof renderWithRouter>['user'], target: string) {
  const email = target === 'member' ? 'alex@example.com' : 'pending@example.com'
  const cells = await screen.findAllByText(email)
  const row = cells[0].closest('tr') as HTMLElement
  await user.click(within(row).getByRole('button'))
  if (target === 'member') await user.click(screen.getByText('org.team.members.actions.remove'))
}

describe('TeamPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('confirm', vi.fn(() => true))

    mockUseAuth.mockReturnValue({
      organizationId: 'auth-org',
      isAuthenticated: true,
      user: { user_id: 'user_1', id: 'legacy_user', email: 'owner@example.com' },
    })
    mockUseConsole.mockReturnValue({
      activeOrgId: 'console-org',
    })
    mockHasPermission.mockReturnValue(true)
    permissionState.isLoading = false
    mockPermissionInstance.mockReset().mockReturnValue(permissionState)
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
    vi.restoreAllMocks()
  })

  it('keeps native active, invited, pending, and deactivated memberships in their correct sections', async () => {
    mockListMembers.mockResolvedValue([
      { id: 'active-member', user_id: 'active-user', email: 'active@example.com', status: 'active', roles: [], is_owner: false },
      { id: 'invited-member', email: 'invited@example.com', status: 'invited', roles: [], is_owner: false },
      { id: 'pending-member', user_id: 'pending-user', email: 'approval@example.com', status: 'pending', roles: [], is_owner: false },
      { id: 'deactivated-member', user_id: 'deactivated-user', email: 'deactivated@example.com', status: 'deactivated', roles: [], is_owner: false },
    ])

    renderWithRouter(<TeamPage />)

    await screen.findByText('org.team.invites.count:1')
    expect(screen.getByText('org.team.members.count:1')).toBeInTheDocument()
    const activeTable = screen.getByRole('table', { name: 'org.team.members.title' })
    const invitationTable = screen.getByRole('table', { name: 'org.team.invites.title' })
    const statusTable = screen.getByRole('table', { name: 'org.team.memberships.title' })
    expect(within(activeTable).getAllByText('active@example.com')).toHaveLength(2)
    expect(within(invitationTable).getByText('invited@example.com')).toBeInTheDocument()
    expect(within(invitationTable).getByRole('button', { name: 'org.team.invites.actions.revoke' })).toBeInTheDocument()
    const pendingRow = within(statusTable).getAllByText('approval@example.com')[0].closest('tr') as HTMLElement
    const deactivatedRow = within(statusTable).getAllByText('deactivated@example.com')[0].closest('tr') as HTMLElement
    expect(within(pendingRow).getByText('org.team.memberships.pending')).toBeInTheDocument()
    expect(within(deactivatedRow).getByText('org.team.memberships.deactivated')).toBeInTheDocument()
    expect(within(statusTable).queryByRole('button')).not.toBeInTheDocument()
    expect(within(statusTable).queryByText('org.team.members.actions.changeRole')).not.toBeInTheDocument()
    expect(mockInviteMember).not.toHaveBeenCalled()
    expect(mockRemoveMember).not.toHaveBeenCalled()
    expect(mockSetMemberRoles).not.toHaveBeenCalled()
  })

  it('does not present approval requests or deactivated memberships as revocable invitations', async () => {
    mockListMembers.mockResolvedValue([
      { id: 'pending-member', user_id: 'pending-user', email: 'approval@example.com', status: 'pending', roles: [] },
      { id: 'deactivated-member', user_id: 'deactivated-user', email: 'deactivated@example.com', status: 'deactivated', roles: [] },
    ])

    renderWithRouter(<TeamPage />)

    await screen.findAllByText('approval@example.com')
    expect(screen.queryByText('org.team.invites.title')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'org.team.invites.actions.revoke' })).not.toBeInTheDocument()
    expect(screen.getByText('org.team.memberships.pending')).toBeInTheDocument()
    expect(screen.getByText('org.team.memberships.deactivated')).toBeInTheDocument()
  })

  it('keeps unrecognized and missing membership statuses visible without invitation or management actions', async () => {
    mockListMembers.mockResolvedValue([
      { id: 'future-member', user_id: 'future-user', email: 'future@example.com', status: 'suspended', roles: [] },
      { id: 'missing-status-member', user_id: 'missing-user', email: 'missing@example.com', roles: [] },
    ])

    renderWithRouter(<TeamPage />)

    await screen.findAllByText('future@example.com')
    expect(screen.queryByText('org.team.invites.title')).not.toBeInTheDocument()
    const statusTable = screen.getByRole('table', { name: 'org.team.memberships.title' })
    expect(within(statusTable).getByText('suspended')).toBeInTheDocument()
    expect(within(statusTable).getByText('org.team.memberships.unknown')).toBeInTheDocument()
    expect(within(statusTable).getAllByText('missing@example.com')).toHaveLength(2)
    expect(within(statusTable).queryByRole('button')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'org.team.memberships.reviewRequests' })).not.toBeInTheDocument()
  })

  it.each([
    { permission: true, loading: false, visible: true },
    { permission: false, loading: false, visible: false },
    { permission: true, loading: true, visible: false },
  ])('links pending approvals only with resolved team:view ($permission, loading=$loading)', async ({ permission, loading, visible }) => {
    mockHasPermission.mockImplementation((resource: string, action: string) => permission && resource === 'team' && action === 'view')
    permissionState.isLoading = loading
    mockListMembers.mockResolvedValue([
      { id: 'pending-member', user_id: 'pending-user', email: 'approval@example.com', status: 'pending', roles: [] },
    ])

    const { user } = renderWithRouter(<TeamWithLocation />, { initialEntries: ['/console/org/team'] })

    await screen.findAllByText('approval@example.com')
    const link = screen.queryByRole('link', { name: 'org.team.memberships.reviewRequests' })
    if (visible) {
      expect(link).toHaveAttribute('href', '/console/org/membership-requests')
      await user.click(link as HTMLElement)
      expect(screen.getByTestId('current-location')).toHaveTextContent('/console/org/membership-requests')
    } else {
      expect(link).not.toBeInTheDocument()
    }
    expect(mockRemoveMember).not.toHaveBeenCalled()
    expect(mockSetMemberRoles).not.toHaveBeenCalled()
  })

  it('removes the approval link immediately when team:view is lost', async () => {
    mockListMembers.mockResolvedValue([
      { id: 'pending-member', user_id: 'pending-user', email: 'approval@example.com', status: 'pending', roles: [] },
    ])
    const { rerender } = renderWithRouter(<TeamPage />)
    await screen.findByRole('link', { name: 'org.team.memberships.reviewRequests' })

    mockHasPermission.mockReturnValue(false)
    rerender(<TeamPage />)

    expect(screen.queryByRole('link', { name: 'org.team.memberships.reviewRequests' })).not.toBeInTheDocument()
    expect(screen.getAllByText('approval@example.com')).toHaveLength(2)
  })

  it('discards prior-scope approval records and links while a different organization loads', async () => {
    mockListMembers.mockResolvedValueOnce([
      { id: 'pending-member', user_id: 'pending-user', email: 'approval@example.com', status: 'pending', roles: [] },
    ])
    const nextMembers = deferred<unknown[]>()
    mockListMembers.mockReturnValueOnce(nextMembers.promise)
    const { rerender } = renderWithRouter(<TeamPage />)
    await screen.findByRole('link', { name: 'org.team.memberships.reviewRequests' })

    mockUseConsole.mockReturnValue({ activeOrgId: 'next-org' })
    rerender(<TeamPage />)

    expect(screen.queryByText('approval@example.com')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'org.team.memberships.reviewRequests' })).not.toBeInTheDocument()
    await act(async () => nextMembers.resolve([
      { id: 'next-member', user_id: 'next-user', email: 'next@example.com', status: 'deactivated', roles: [] },
    ]))
    await screen.findAllByText('next@example.com')
    expect(screen.getByText('org.team.memberships.deactivated')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'org.team.memberships.reviewRequests' })).not.toBeInTheDocument()
  })

  it('uses the native session identity for the current member when owner membership omits profile fields', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      user: { user_id: 'user_1', name: 'UX Crawl', email: 'owner@example.com' },
    })
    mockListMembers.mockResolvedValue([{
      id: 'owner-membership', organization_id: 'console-org', user_id: 'user_1',
      status: 'active', is_owner: true, roles: [{ id: 'owner-role', name: 'owner', display_name: 'Owner' }],
    }])

    renderWithRouter(<TeamPage />)

    const row = (await screen.findByText('UX Crawl')).closest('tr') as HTMLElement
    expect(within(row).getByText('owner@example.com')).toBeInTheDocument()
    expect(within(row).getByText('Owner')).toBeInTheDocument()
    expect(within(row).queryByRole('button')).not.toBeInTheDocument()
    expect(screen.queryByText('user_1')).not.toBeInTheDocument()
  })

  it('preserves a current member name and email supplied by membership data', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      user: { user_id: 'user_1', name: 'Session Name', email: 'owner@example.com' },
    })
    mockListMembers.mockResolvedValue([{
      id: 'member_1', user_id: 'user_1', name: 'Member Name', email: 'member@example.com',
      status: 'active', roles: [],
    }])

    renderWithRouter(<TeamPage />)

    const row = (await screen.findByText('Member Name')).closest('tr') as HTMLElement
    expect(within(row).getByText('member@example.com')).toBeInTheDocument()
    expect(screen.queryByText('Session Name')).not.toBeInTheDocument()
    expect(screen.queryByText('owner@example.com')).not.toBeInTheDocument()
  })

  it.each(['legacy_user', 'other-user', undefined])('does not apply the session profile to a member with a different native user_id (%s)', async (userId) => {
    mockListMembers.mockResolvedValue([{
      id: 'user_1', user_id: userId, status: 'active', roles: [],
    }])

    renderWithRouter(<TeamPage />)

    const row = (await screen.findByText(userId || 'user_1')).closest('tr') as HTMLElement
    expect(within(row).getAllByRole('cell')[1]).toHaveTextContent(/^-$/)
    expect(screen.queryByText('owner@example.com')).not.toBeInTheDocument()
  })

  it('updates the self-row fallback across native account changes without mutating membership records', async () => {
    const members = [
      { id: 'member_1', user_id: 'user_1', status: 'active', roles: [] },
      { id: 'member_2', user_id: 'user_2', status: 'active', roles: [] },
    ]
    mockListMembers.mockResolvedValue(members)
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      user: { user_id: 'user_1', name: 'First Owner', email: 'first@example.com' },
    })
    const { rerender } = renderWithRouter(<TeamPage />)
    await screen.findByText('First Owner')

    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      user: { user_id: 'user_2', given_name: 'Second', family_name: 'Owner', email: 'second@example.com' },
    })
    rerender(<TeamPage />)

    const currentRow = (await screen.findByText('Second Owner')).closest('tr') as HTMLElement
    expect(within(currentRow).getByText('second@example.com')).toBeInTheDocument()
    expect(screen.getByText('user_1')).toBeInTheDocument()
    expect(screen.queryByText('First Owner')).not.toBeInTheDocument()
    expect(screen.queryByText('first@example.com')).not.toBeInTheDocument()
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

  it('keeps manual Invite disabled when the gate resolves before the page permission request', async () => {
    const pagePermissions = { isLoading: true, can: () => false }
    const gatePermissions = { isLoading: false, can: () => true }
    // Each real hook consumer retains its own state. The page mounts before
    // its child gate, whose independent permission request finishes first.
    mockPermissionInstance.mockReturnValue(gatePermissions).mockReturnValueOnce(pagePermissions)
    const { user, rerender } = renderWithRouter(<TeamPage />, {
      initialEntries: ['/console/org/team'],
    })

    await waitFor(() => expect(screen.getAllByText('alex@example.com').length).toBeGreaterThan(0))
    const invite = screen.getByRole('button', { name: 'org.team.members.actions.invite' })
    expect(invite).toBeVisible()
    expect(invite).toBeDisabled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    pagePermissions.isLoading = false
    pagePermissions.can = () => true
    rerender(<TeamPage />)
    await waitFor(() => expect(invite).toBeEnabled())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(invite)
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })

  it.each(['dashboard.team.invite', 'dashboard.team.inviteTeamMember'])(
    'opens the team invitation from the dashboard %s link and consumes its intent',
    async (action) => {
      const roles = deferred<unknown>()
      mockListRoles.mockReturnValueOnce(roles.promise)
      const { user } = renderWithRouter(<>
        <Routes>
          <Route path="/console/org" element={<TeamSnapshotPanel teamData={{ members: [] }} />} />
          <Route path="/console/org/team" element={<TeamPage />} />
        </Routes>
        <CurrentLocation />
      </>, { initialEntries: ['/console/org'] })

      await user.click(screen.getByRole('link', { name: action }))
      // jsdom leaves Document focused when the old route's focused link is
      // removed. Match the browser's body focus before the async dialog opens.
      document.body.focus()
      await act(async () => roles.resolve({ roles: [{
        id: 'role_viewer', name: 'viewer', display_name: 'Viewer', is_default_for_new_members: true,
      }] }))

      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel')).toHaveValue('')
      expect(mockListRoles).toHaveBeenCalledWith('console-org')
      await waitFor(() => expect(screen.getByTestId('current-location')).toHaveTextContent(/^\/console\/org\/team$/))

      await user.click(within(dialog).getByRole('button', { name: 'actions.cancel' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByTestId('current-location')).toHaveTextContent(/^\/console\/org\/team$/)
      expect(mockInviteMember).not.toHaveBeenCalled()
    },
  )

  it.each([false, true])('hides dashboard invitation actions without resolved invite permission (loading=%s)', (isLoading) => {
    permissionState.isLoading = isLoading
    mockHasPermission.mockReturnValue(isLoading)
    renderWithRouter(<TeamSnapshotPanel teamData={{ members: [] }} />)

    expect(screen.queryByRole('link', { name: 'dashboard.team.invite' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'dashboard.team.inviteTeamMember' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'dashboard.team.manage' })).toBeInTheDocument()
  })

  it('waits for roles and permissions before opening a requested invitation and preserves other query parameters', async () => {
    const roles = deferred<unknown>()
    mockListRoles.mockReturnValueOnce(roles.promise)
    permissionState.isLoading = true
    const { rerender } = renderWithRouter(<TeamWithLocation />, {
      initialEntries: ['/console/org/team?invite=1&view=members'],
    })

    await waitFor(() => expect(mockListRoles).toHaveBeenCalledWith('console-org'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await act(async () => roles.resolve({ roles: [{
      id: 'loaded-role', name: 'viewer', display_name: 'Loaded viewer', is_default_for_new_members: true,
    }] }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByTestId('current-location')).toHaveTextContent('invite=1')

    permissionState.isLoading = false
    rerender(<TeamWithLocation />)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Loaded viewer')).toBeInTheDocument()
    expect(within(dialog).getByRole('checkbox')).toBeChecked()
    expect(screen.getByTestId('current-location')).toHaveTextContent(/^\/console\/org\/team\?view=members$/)
  })

  it('does not open an invitation requested by a member without invite permission', async () => {
    mockHasPermission.mockImplementation((resource: string, action: string) => (
      resource === 'team' && action === 'view'
    ))
    renderWithRouter(<TeamWithLocation />, { initialEntries: ['/console/org/team?invite=1'] })

    await waitFor(() => expect(screen.getAllByText('alex@example.com').length).toBeGreaterThan(0))
    await waitFor(() => expect(screen.getByTestId('current-location')).toHaveTextContent(/^\/console\/org\/team$/))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'org.team.members.actions.invite' })).not.toBeInTheDocument()
    expect(mockInviteMember).not.toHaveBeenCalled()
  })

  it('ignores a previous organization response before opening and submitting an invitation', async () => {
    const firstRoles = deferred<unknown>()
    const currentRoles = deferred<unknown>()
    mockListRoles.mockImplementation((orgId: string) => (
      orgId === 'console-org' ? firstRoles.promise : currentRoles.promise
    ))
    const { user, rerender } = renderWithRouter(<TeamWithLocation />, {
      initialEntries: ['/console/org/team?invite=1'],
    })
    await waitFor(() => expect(mockListRoles).toHaveBeenCalledWith('console-org'))

    mockUseConsole.mockReturnValue({ activeOrgId: 'current-org' })
    rerender(<TeamWithLocation />)
    await waitFor(() => expect(mockListRoles).toHaveBeenCalledWith('current-org'))
    await act(async () => firstRoles.resolve({ roles: [{
      id: 'old-role', name: 'viewer', display_name: 'Old organization role', is_default_for_new_members: true,
    }] }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByTestId('current-location')).toHaveTextContent('invite=1')

    await act(async () => currentRoles.resolve({ roles: [{
      id: 'current-role', name: 'viewer', display_name: 'Current organization role', is_default_for_new_members: true,
    }] }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByText('Old organization role')).not.toBeInTheDocument()
    expect(within(dialog).getByText('Current organization role')).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel'), 'new.member@example.com')
    await user.click(within(dialog).getByRole('button', { name: 'org.team.dialog.invite.send' }))
    await waitFor(() => expect(mockInviteMember).toHaveBeenCalledWith('current-org', {
      email: 'new.member@example.com', role_ids: ['current-role'],
    }))
  })

  it('closes the invitation and discards entered data when the active organization changes', async () => {
    const { user, rerender } = renderWithRouter(<TeamWithLocation />, {
      initialEntries: ['/console/org/team?invite=1'],
    })
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel'), 'old.org@example.com')

    mockUseConsole.mockReturnValue({ activeOrgId: 'current-org' })
    rerender(<TeamWithLocation />)
    await waitFor(() => {
      expect(mockListRoles).toHaveBeenCalledWith('current-org')
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
    await user.click(screen.getByRole('button', { name: 'org.team.members.actions.invite' }))
    expect(within(await screen.findByRole('dialog')).getByLabelText('org.team.dialog.invite.emailLabel')).toHaveValue('')
    expect(mockInviteMember).not.toHaveBeenCalled()
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

    renderWithRouter(<TeamWithLocation />, {
      initialEntries: ['/console/org/team?invite=1'],
    })

    expect((await screen.findAllByText(/Roles service unavailable/i)).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'org.team.members.actions.invite' })).toBeDisabled()
    expect(screen.queryByText('alex@example.com')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByTestId('current-location')).toHaveTextContent('invite=1')
  })

  it('lets keyboard users select invitation roles with Tab and Space', async () => {
    const { user } = renderWithRouter(<TeamPage />, { initialEntries: ['/console/org/team?invite=1'] })
    const dialog = await screen.findByRole('dialog')
    const viewer = within(dialog).getByRole('checkbox', { name: 'Viewer' })
    const operator = within(dialog).getByRole('checkbox', { name: 'Operator' })
    await user.tab()
    expect(viewer).toHaveFocus()
    await user.keyboard(' ')
    expect(viewer).not.toBeChecked()
    await user.tab()
    expect(operator).toHaveFocus()
    await user.keyboard(' ')
    expect(operator).toBeChecked()
    expect(mockInviteMember).not.toHaveBeenCalled()
  })

  it('lets keyboard users select member roles with Tab and Space', async () => {
    const { user } = renderWithRouter(<TeamPage />)
    const dialog = await openRoleDialog(user)
    const viewer = within(dialog).getByRole('checkbox', { name: 'Viewer' })
    await user.tab()
    expect(viewer).toHaveFocus()
    await user.keyboard(' ')
    expect(viewer).toBeChecked()
    expect(mockSetMemberRoles).not.toHaveBeenCalled()
  })

  it('discards a role dialog on organization change and submits only the new organization member', async () => {
    mockListMembers.mockImplementation((organizationId: string) => Promise.resolve([{
      id: organizationId === 'console-org' ? 'member_1' : 'current_member',
      email: organizationId === 'console-org' ? 'alex@example.com' : 'current@example.com',
      roles: [], status: 'active', is_owner: false,
    }]))
    const { user, rerender } = renderWithRouter(<TeamPage />)
    await openRoleDialog(user)
    await user.click(screen.getByRole('checkbox', { name: 'Operator' }))
    mockUseConsole.mockReturnValue({ activeOrgId: 'current-org' })
    rerender(<TeamPage />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(mockSetMemberRoles).not.toHaveBeenCalled()

    const currentDialog = await openRoleDialog(user, 'current@example.com')
    expect(within(currentDialog).getByRole('checkbox', { name: 'Operator' })).not.toBeChecked()
    await user.click(within(currentDialog).getByRole('checkbox', { name: 'Operator' }))
    await user.click(within(currentDialog).getByRole('button', { name: 'org.team.dialog.changeRole.update' }))
    await waitFor(() => expect(mockSetMemberRoles).toHaveBeenCalledExactlyOnceWith('current-org', 'current_member', ['role_operator']))
  })

  it.each(['resolve', 'reject'] as const)('ignores a late role update %s after leaving and returning to the organization', async (completion) => {
    const request = deferred<unknown>()
    mockSetMemberRoles.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<TeamPage />)
    const originalDialog = await openRoleDialog(user)
    await user.click(within(originalDialog).getByRole('checkbox', { name: 'Operator' }))
    await user.click(within(originalDialog).getByRole('button', { name: 'org.team.dialog.changeRole.update' }))
    expect(within(originalDialog).getByRole('button', { name: 'actions.cancel' })).toBeDisabled()
    expect(within(originalDialog).getByRole('checkbox', { name: 'Operator' })).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    mockUseConsole.mockReturnValue({ activeOrgId: 'another-org' })
    rerender(<TeamPage />)
    await waitFor(() => expect(mockListMembers).toHaveBeenLastCalledWith('another-org'))
    mockUseConsole.mockReturnValue({ activeOrgId: 'console-org' })
    rerender(<TeamPage />)
    const replacementDialog = await openRoleDialog(user)
    await act(async () => {
      if (completion === 'resolve') request.resolve({ ok: true })
      else request.reject(new Error('Previous role update failed'))
    })

    expect(screen.getByRole('dialog')).toBe(replacementDialog)
    expect(within(replacementDialog).getByRole('checkbox', { name: 'Operator' })).not.toBeChecked()
    expect(within(replacementDialog).getByRole('button', { name: 'org.team.dialog.changeRole.update' })).toBeEnabled()
    expect(screen.queryByText('Previous role update failed')).not.toBeInTheDocument()
    expect(mockShowNotification).not.toHaveBeenCalled()
    expect(mockRefreshPermissions).not.toHaveBeenCalled()
    expect(mockSetMemberRoles).toHaveBeenCalledExactlyOnceWith('console-org', 'member_1', ['role_admin', 'role_operator'])
  })

  it('does not reload the old team after its permission refresh completes in a different organization', async () => {
    const refresh = deferred<unknown>()
    mockRefreshPermissions.mockReturnValueOnce(refresh.promise)
    const { user, rerender } = renderWithRouter(<TeamPage />)
    const dialog = await openRoleDialog(user)
    await user.click(within(dialog).getByRole('button', { name: 'org.team.dialog.changeRole.update' }))
    await waitFor(() => expect(mockRefreshPermissions).toHaveBeenCalledOnce())
    mockUseConsole.mockReturnValue({ activeOrgId: 'current-org' })
    rerender(<TeamPage />)
    await waitFor(() => expect(mockListMembers).toHaveBeenLastCalledWith('current-org'))
    await act(async () => refresh.resolve(undefined))
    expect(mockListMembers.mock.calls.map(([organizationId]) => organizationId)).toEqual(['console-org', 'current-org'])
  })

  it('keeps a failed role update open and makes the selected roles editable for retry', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockSetMemberRoles.mockRejectedValueOnce(new Error('Role assignment is unavailable'))
    const { user } = renderWithRouter(<TeamPage />)
    const dialog = await openRoleDialog(user)
    await user.click(within(dialog).getByRole('checkbox', { name: 'Operator' }))
    await user.click(within(dialog).getByRole('button', { name: 'org.team.dialog.changeRole.update' }))
    expect(await within(dialog).findByText('Role assignment is unavailable')).toBeInTheDocument()
    expect(within(dialog).getByRole('checkbox', { name: 'Operator' })).toBeChecked()
    expect(within(dialog).getByRole('checkbox', { name: 'Operator' })).toBeEnabled()
    expect(within(dialog).getByRole('button', { name: 'org.team.dialog.changeRole.update' })).toBeEnabled()
  })

  it('closes a role dialog when management permission is no longer available', async () => {
    const { user, rerender } = renderWithRouter(<TeamPage />)
    await openRoleDialog(user)
    mockHasPermission.mockImplementation((resource: string, action: string) => resource === 'team' && action === 'view')
    rerender(<TeamPage />)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockSetMemberRoles).not.toHaveBeenCalled()
  })

  it.each([
    { target: 'member', completion: 'resolve' },
    { target: 'member', completion: 'reject' },
    { target: 'invitation', completion: 'resolve' },
    { target: 'invitation', completion: 'reject' },
  ])('ignores a late $target removal $completion after switching organizations', async ({ target, completion }) => {
    mockListMembers.mockImplementation((organizationId: string) => Promise.resolve(organizationId === 'console-org' ? [
      { id: 'member_1', email: 'alex@example.com', status: 'active', roles: [], is_owner: false },
      { id: 'member_invite_1', email: 'pending@example.com', status: 'invited', roles: [], is_owner: false },
    ] : [
      { id: 'current_member', email: 'current@example.com', status: 'active', roles: [], is_owner: false },
    ]))
    const request = deferred<unknown>()
    mockRemoveMember.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<TeamPage />)
    await startRemoval(user, target)
    expect(mockRemoveMember).toHaveBeenCalledExactlyOnceWith('console-org', target === 'member' ? 'member_1' : 'member_invite_1')

    mockUseConsole.mockReturnValue({ activeOrgId: 'current-org' })
    rerender(<TeamPage />)
    await screen.findAllByText('current@example.com')
    await act(async () => {
      if (completion === 'resolve') request.resolve({ ok: true })
      else request.reject(new Error('Previous organization removal failed'))
    })

    expect(mockListMembers.mock.calls.map(([organizationId]) => organizationId)).toEqual(['console-org', 'current-org'])
    expect(mockListRoles.mock.calls.map(([organizationId]) => organizationId)).toEqual(['console-org', 'current-org'])
    expect(screen.getAllByText('current@example.com').length).toBeGreaterThan(0)
    expect(screen.queryByText('alex@example.com')).not.toBeInTheDocument()
    expect(mockShowNotification).not.toHaveBeenCalled()
  })

  it.each(['member', 'invitation'])('does not reload or notify after a pending %s removal outlives the page', async (target) => {
    const request = deferred<unknown>()
    mockRemoveMember.mockReturnValueOnce(request.promise)
    const { user, unmount } = renderWithRouter(<TeamPage />)
    await startRemoval(user, target)
    expect(mockRemoveMember).toHaveBeenCalledOnce()
    unmount()
    await act(async () => request.resolve({ ok: true }))

    expect(mockListMembers).toHaveBeenCalledExactlyOnceWith('console-org')
    expect(mockShowNotification).not.toHaveBeenCalled()
  })

  it('blocks duplicate invitation submissions and dismissal while sending', async () => {
    const request = deferred<unknown>()
    mockInviteMember.mockReturnValueOnce(request.promise)
    const { user } = renderWithRouter(<TeamPage />, { initialEntries: ['/console/org/team?invite=1'] })
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel'), 'new.member@example.com')
    const send = within(dialog).getByRole('button', { name: 'org.team.dialog.invite.send' })
    await act(async () => {
      fireEvent.click(send)
      fireEvent.click(send)
    })

    expect(mockInviteMember).toHaveBeenCalledExactlyOnceWith('console-org', {
      email: 'new.member@example.com', role_ids: ['role_viewer'],
    })
    expect(send).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: 'actions.cancel' })).toBeDisabled()
    expect(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel')).toBeDisabled()
    expect(within(dialog).getByRole('checkbox', { name: 'Viewer' })).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBe(dialog)

    await act(async () => request.resolve({ id: 'invite-new' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockShowNotification).toHaveBeenCalledExactlyOnceWith('org.team.dialog.invite.success', 'success')
  })

  it.each(['resolve', 'reject'] as const)('ignores an old invitation %s after permission refresh replaces its dialog', async (completion) => {
    const request = deferred<unknown>()
    mockInviteMember.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<TeamPage />, { initialEntries: ['/console/org/team?invite=1'] })
    const original = await screen.findByRole('dialog')
    await user.type(within(original).getByLabelText('org.team.dialog.invite.emailLabel'), 'old.invitation@example.com')
    await user.click(within(original).getByRole('button', { name: 'org.team.dialog.invite.send' }))

    permissionState.isLoading = true
    rerender(<TeamPage />)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    permissionState.isLoading = false
    rerender(<TeamPage />)
    await user.click(screen.getByRole('button', { name: 'org.team.members.actions.invite' }))
    const replacement = await screen.findByRole('dialog')
    await user.type(within(replacement).getByLabelText('org.team.dialog.invite.emailLabel'), 'current.invitation@example.com')

    await act(async () => {
      if (completion === 'resolve') request.resolve({ id: 'old-invitation' })
      else request.reject(new Error('Previous invitation failed'))
    })

    expect(screen.getByRole('dialog')).toBe(replacement)
    expect(within(replacement).getByLabelText('org.team.dialog.invite.emailLabel')).toHaveValue('current.invitation@example.com')
    expect(within(replacement).getByRole('button', { name: 'org.team.dialog.invite.send' })).toBeEnabled()
    expect(screen.queryByText('Previous invitation failed')).not.toBeInTheDocument()
    expect(mockShowNotification).not.toHaveBeenCalled()
    expect(mockListMembers).toHaveBeenCalledExactlyOnceWith('console-org')
    expect(mockListRoles).toHaveBeenCalledExactlyOnceWith('console-org')
  })

  it('keeps a failed invitation draft available for correction and retry', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockInviteMember.mockRejectedValueOnce(new Error('Invitation service is unavailable'))
      .mockResolvedValueOnce({ id: 'retried-invitation' })
    const { user } = renderWithRouter(<TeamPage />, { initialEntries: ['/console/org/team?invite=1'] })
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel'), 'new.member@example.com')
    await user.click(within(dialog).getByRole('checkbox', { name: 'Operator' }))
    await user.click(within(dialog).getByRole('button', { name: 'org.team.dialog.invite.send' }))

    expect(await within(dialog).findByText('Invitation service is unavailable')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel')).toHaveValue('new.member@example.com')
    expect(within(dialog).getByRole('checkbox', { name: 'Operator' })).toBeChecked()
    expect(within(dialog).getByRole('checkbox', { name: 'Operator' })).toBeEnabled()
    await user.click(within(dialog).getByRole('button', { name: 'org.team.dialog.invite.send' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockInviteMember).toHaveBeenCalledTimes(2)
    expect(mockInviteMember).toHaveBeenLastCalledWith('console-org', {
      email: 'new.member@example.com', role_ids: ['role_viewer', 'role_operator'],
    })
    expect(mockShowNotification).toHaveBeenCalledExactlyOnceWith('org.team.dialog.invite.success', 'success')
  })

  it.each(['resolve', 'reject'] as const)('discards an old invitation %s when the native account changes in the same organization', async (completion) => {
    const request = deferred<unknown>()
    const currentMembers = deferred<unknown>()
    mockInviteMember.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<TeamPage />, { initialEntries: ['/console/org/team?invite=1'] })
    const original = await screen.findByRole('dialog')
    await user.type(within(original).getByLabelText('org.team.dialog.invite.emailLabel'), 'previous.account@example.com')
    await user.click(within(original).getByRole('button', { name: 'org.team.dialog.invite.send' }))

    mockUseAuth.mockReturnValue({
      organizationId: 'auth-org',
      isAuthenticated: true,
      user: { user_id: 'user_3', id: 'legacy_user', email: 'current.owner@example.com' },
    })
    mockListMembers.mockReturnValueOnce(currentMembers.promise)
    rerender(<TeamPage />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('alex@example.com')).not.toBeInTheDocument()
    await act(async () => currentMembers.resolve([{
      id: 'current_member', email: 'current@example.com', roles: [], status: 'active', is_owner: false,
    }]))
    expect((await screen.findAllByText('current@example.com')).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('button', { name: 'org.team.members.actions.invite' }))
    const replacement = await screen.findByRole('dialog')
    expect(within(replacement).getByLabelText('org.team.dialog.invite.emailLabel')).toHaveValue('')
    await user.type(within(replacement).getByLabelText('org.team.dialog.invite.emailLabel'), 'current.invitation@example.com')

    await act(async () => {
      if (completion === 'resolve') request.resolve({ id: 'previous-invitation' })
      else request.reject(new Error('Previous account invitation failed'))
    })

    expect(screen.getByRole('dialog')).toBe(replacement)
    expect(within(replacement).getByLabelText('org.team.dialog.invite.emailLabel')).toHaveValue('current.invitation@example.com')
    expect(within(replacement).getByRole('button', { name: 'org.team.dialog.invite.send' })).toBeEnabled()
    expect(screen.queryByText('Previous account invitation failed')).not.toBeInTheDocument()
    expect(mockShowNotification).not.toHaveBeenCalled()
    expect(mockListMembers).toHaveBeenCalledTimes(2)
    expect(mockListRoles).toHaveBeenCalledTimes(2)
    expect(mockInviteMember).toHaveBeenCalledExactlyOnceWith('console-org', {
      email: 'previous.account@example.com', role_ids: ['role_viewer'],
    })
  })

  it.each(['resolve', 'reject'] as const)('does not reload or notify after a pending invitation %s outlives the page', async (completion) => {
    const request = deferred<unknown>()
    mockInviteMember.mockReturnValueOnce(request.promise)
    const { user, unmount } = renderWithRouter(<TeamPage />, { initialEntries: ['/console/org/team?invite=1'] })
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('org.team.dialog.invite.emailLabel'), 'new.member@example.com')
    await user.click(within(dialog).getByRole('button', { name: 'org.team.dialog.invite.send' }))
    unmount()

    await act(async () => {
      if (completion === 'resolve') request.resolve({ id: 'old-invitation' })
      else request.reject(new Error('Previous invitation failed'))
    })

    expect(mockListMembers).toHaveBeenCalledExactlyOnceWith('console-org')
    expect(mockListRoles).toHaveBeenCalledExactlyOnceWith('console-org')
    expect(mockShowNotification).not.toHaveBeenCalled()
  })
})
