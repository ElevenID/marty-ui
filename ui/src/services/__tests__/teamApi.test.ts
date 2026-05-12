import { beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  getMember,
  getTeamSnapshot,
  inviteMember,
  listMembers,
  removeMember,
  transferOwnership,
} from '../teamApi'

describe('teamApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists members for an organization with filters', async () => {
    let orgId
    let queryParams

    server.use(
      http.get('*/v1/organizations/:orgId/members', ({ params, request }) => {
        orgId = params.orgId
        queryParams = new URL(request.url).searchParams
        return HttpResponse.json([
          { id: 'member_1', email: 'alex@example.com', status: 'active' },
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
    let orgId
    let memberId

    server.use(
      http.get('*/v1/organizations/:orgId/members/:memberId', ({ params }) => {
        orgId = params.orgId
        memberId = params.memberId
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

  it('creates a member invite in an organization scope using role_ids', async () => {
    const invite = {
      email: 'new.user@example.com',
      role_ids: ['role-operator', 'role-reviewer'],
    }
    let orgId
    let receivedBody

    server.use(
      http.post('*/v1/organizations/:orgId/members', async ({ params, request }) => {
        orgId = params.orgId
        receivedBody = await request.json()
        return HttpResponse.json({ id: 'member_invite_123', ...receivedBody }, { status: 201 })
      })
    )

    const result = await inviteMember('org_123', invite)

    expect(orgId).toBe('org_123')
    expect(receivedBody).toEqual(invite)
    expect(result.id).toBe('member_invite_123')
  })

  it('removes a member through the org-scoped endpoint', async () => {
    let orgId
    let memberId

    server.use(
      http.delete('*/v1/organizations/:orgId/members/:memberId', ({ params }) => {
        orgId = params.orgId
        memberId = params.memberId
        return HttpResponse.json({ ok: true })
      })
    )

    await removeMember('org_123', 'member_7')

    expect(orgId).toBe('org_123')
    expect(memberId).toBe('member_7')
  })

  it('transfers organization ownership', async () => {
    let orgId
    let receivedBody

    server.use(
      http.post('*/v1/organizations/:orgId/transfer-ownership', async ({ params, request }) => {
        orgId = params.orgId
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
    let orgId

    server.use(
      http.get('*/v1/organizations/:orgId/team/snapshot', ({ params }) => {
        orgId = params.orgId
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
