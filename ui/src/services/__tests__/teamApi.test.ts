import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  listMembers,
  getMember,
  inviteMember,
  listInvites,
  resendInvite,
  revokeInvite,
  updateMemberRole,
  removeMember,
  transferOwnership,
  getTeamSnapshot,
} from '../teamApi'

describe('teamApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists members for an organization with filters', async () => {
    let orgId: string | undefined
    let queryParams: URLSearchParams | undefined

    server.use(
      http.get('*/v1/organizations/:orgId/members', ({ params, request }) => {
        orgId = params.orgId as string
        queryParams = new URL(request.url).searchParams
        return HttpResponse.json([
          { id: 'member_1', email: 'alex@example.com', role: 'admin' },
        ])
      })
    )

    const members = await listMembers('org_123', { role: 'admin', status: 'active' })

    expect(orgId).toBe('org_123')
    expect(queryParams?.get('role')).toBe('admin')
    expect(queryParams?.get('status')).toBe('active')
    expect(members).toHaveLength(1)
  })

  it('gets a member by id', async () => {
    let orgId: string | undefined
    let memberId: string | undefined

    server.use(
      http.get('*/v1/organizations/:orgId/members/:memberId', ({ params }) => {
        orgId = params.orgId as string
        memberId = params.memberId as string
        return HttpResponse.json({
          id: memberId,
          organization_id: orgId,
          email: 'alex@example.com',
        })
      })
    )

    const member = await getMember('org_123', 'member_42')

    expect(orgId).toBe('org_123')
    expect(memberId).toBe('member_42')
    expect(member.id).toBe('member_42')
  })

  it('creates an invite in an organization scope', async () => {
    const invite = {
      email: 'new.user@example.com',
      role: 'developer',
      message: 'Welcome aboard',
    }
    let orgId: string | undefined
    let receivedBody: any

    server.use(
      http.post('*/v1/organizations/:orgId/invites', async ({ params, request }) => {
        orgId = params.orgId as string
        receivedBody = await request.json()
        return HttpResponse.json({ id: 'invite_123', ...receivedBody }, { status: 201 })
      })
    )

    const result = await inviteMember('org_123', invite)

    expect(orgId).toBe('org_123')
    expect(receivedBody).toEqual(invite)
    expect(result.id).toBe('invite_123')
  })

  it('lists invites for an organization', async () => {
    let orgId: string | undefined

    server.use(
      http.get('*/v1/organizations/:orgId/invites', ({ params }) => {
        orgId = params.orgId as string
        return HttpResponse.json([
          { id: 'invite_1', email: 'pending@example.com', role: 'operator' },
        ])
      })
    )

    const invites = await listInvites('org_123')

    expect(orgId).toBe('org_123')
    expect(invites).toHaveLength(1)
    expect(invites[0].id).toBe('invite_1')
  })

  it('resends an invite through the org-scoped endpoint', async () => {
    let orgId: string | undefined
    let inviteId: string | undefined
    let receivedBody: any

    server.use(
      http.post('*/v1/organizations/:orgId/invites/:inviteId/resend', async ({ params, request }) => {
        orgId = params.orgId as string
        inviteId = params.inviteId as string
        receivedBody = await request.json()
        return HttpResponse.json({ id: inviteId, resent: true })
      })
    )

    const result = await resendInvite('org_123', 'invite_99')

    expect(orgId).toBe('org_123')
    expect(inviteId).toBe('invite_99')
    expect(receivedBody).toEqual({})
    expect(result.resent).toBe(true)
  })

  it('revokes an invite through the org-scoped endpoint', async () => {
    let orgId: string | undefined
    let inviteId: string | undefined

    server.use(
      http.delete('*/v1/organizations/:orgId/invites/:inviteId', ({ params }) => {
        orgId = params.orgId as string
        inviteId = params.inviteId as string
        return HttpResponse.json({ ok: true })
      })
    )

    await revokeInvite('org_123', 'invite_77')

    expect(orgId).toBe('org_123')
    expect(inviteId).toBe('invite_77')
  })

  it('updates a member role within an organization', async () => {
    let orgId: string | undefined
    let memberId: string | undefined
    let receivedBody: any

    server.use(
      http.patch('*/v1/organizations/:orgId/members/:memberId', async ({ params, request }) => {
        orgId = params.orgId as string
        memberId = params.memberId as string
        receivedBody = await request.json()
        return HttpResponse.json({ id: memberId, ...receivedBody })
      })
    )

    const result = await updateMemberRole('org_123', 'member_9', 'operator')

    expect(orgId).toBe('org_123')
    expect(memberId).toBe('member_9')
    expect(receivedBody).toEqual({ role: 'operator' })
    expect(result.role).toBe('operator')
  })

  it('removes a member through the org-scoped endpoint', async () => {
    let orgId: string | undefined
    let memberId: string | undefined

    server.use(
      http.delete('*/v1/organizations/:orgId/members/:memberId', ({ params }) => {
        orgId = params.orgId as string
        memberId = params.memberId as string
        return HttpResponse.json({ ok: true })
      })
    )

    await removeMember('org_123', 'member_7')

    expect(orgId).toBe('org_123')
    expect(memberId).toBe('member_7')
  })

  it('transfers organization ownership', async () => {
    let orgId: string | undefined
    let receivedBody: any

    server.use(
      http.post('*/v1/organizations/:orgId/transfer-ownership', async ({ params, request }) => {
        orgId = params.orgId as string
        receivedBody = await request.json()
        return HttpResponse.json({ org_id: orgId, ...receivedBody })
      })
    )

    const result = await transferOwnership('org_123', 'user_456')

    expect(orgId).toBe('org_123')
    expect(receivedBody).toEqual({ new_owner_id: 'user_456' })
    expect(result.new_owner_id).toBe('user_456')
  })

  it('gets the team snapshot for an organization', async () => {
    let orgId: string | undefined

    server.use(
      http.get('*/v1/organizations/:orgId/team/snapshot', ({ params }) => {
        orgId = params.orgId as string
        return HttpResponse.json({
          member_count: 5,
          pending_invite_count: 2,
        })
      })
    )

    const snapshot = await getTeamSnapshot('org_123')

    expect(orgId).toBe('org_123')
    expect(snapshot.member_count).toBe(5)
    expect(snapshot.pending_invite_count).toBe(2)
  })
})