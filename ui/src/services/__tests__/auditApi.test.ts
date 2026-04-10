import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  listAuditEvents,
  getAuditEvent,
  exportAuditEvents,
  getCriticalEvents,
  saveFilterView,
  listFilterViews,
} from '../auditApi'

describe('auditApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('applies supported filters when listing audit events', async () => {
    let requestedOrgId: string | undefined
    let queryParams: URLSearchParams | undefined

    server.use(
      http.get('*/v1/organizations/:orgId/audit-events', ({ params, request }) => {
        requestedOrgId = params.orgId as string
        queryParams = new URL(request.url).searchParams
        return HttpResponse.json({
          events: [],
          total: 0,
          page: 1,
          per_page: 25,
        })
      })
    )

    await listAuditEvents('org_123', {
      actor: 'user_1',
      resource_type: 'credential',
      resource_id: 'cred_123',
      action: 'credential.issued',
      search: 'alice',
      severity: 'warning',
      ip_address: '127.0.0.1',
      start_date: '2026-04-10T00:00:00Z',
      end_date: '2026-04-10T12:00:00Z',
      limit: 25,
      offset: 50,
    })

    expect(requestedOrgId).toBe('org_123')
    expect(queryParams?.get('actor')).toBe('user_1')
    expect(queryParams?.get('resource_type')).toBe('credential')
    expect(queryParams?.get('resource_id')).toBe('cred_123')
    expect(queryParams?.get('action')).toBe('credential.issued')
    expect(queryParams?.get('search')).toBe('alice')
    expect(queryParams?.get('severity')).toBe('warning')
    expect(queryParams?.get('ip_address')).toBe('127.0.0.1')
    expect(queryParams?.get('start_date')).toBe('2026-04-10T00:00:00Z')
    expect(queryParams?.get('end_date')).toBe('2026-04-10T12:00:00Z')
    expect(queryParams?.get('limit')).toBe('25')
    expect(queryParams?.get('offset')).toBe('50')
  })

  it('normalizes an audit event by id', async () => {
    let requestedEventId: string | undefined

    server.use(
      http.get('*/v1/organizations/:orgId/audit-events/:eventId', ({ params }) => {
        requestedEventId = params.eventId as string
        return HttpResponse.json({
          id: requestedEventId,
          organization_id: params.orgId,
          timestamp: '2026-04-10T08:00:00Z',
          actor_id: 'user_42',
          actor_type: 'user',
          action: 'team.member.invited',
          resource_type: 'team',
          resource_id: 'team_1',
          resource_name: 'Team workspace',
          changes: null,
          metadata: {
            severity: 'warning',
            ip_address: '127.0.0.1',
          },
        })
      })
    )

    const event = await getAuditEvent('org_123', 'evt_123')

    expect(requestedEventId).toBe('evt_123')
    expect(event.id).toBe('evt_123')
    expect(event.action).toBe('team.member.invited')
    expect(event.actor).toBe('user_42')
    expect(event.category).toBe('team')
    expect(event.resource).toBe('Team workspace')
    expect(event.ipAddress).toBe('127.0.0.1')
  })

  it('builds an audit export download URL with filters and format', async () => {
    const result = await exportAuditEvents(
      'org_123',
      { severity: 'error', actor: 'ops@example.com' },
      'json'
    )

    const url = new URL(result.download_url, 'http://localhost')

    expect(url.pathname).toBe('/v1/organizations/org_123/audit-events/export')
    expect(url.searchParams.get('format')).toBe('json')
    expect(url.searchParams.get('severity')).toBe('error')
    expect(url.searchParams.get('actor')).toBe('ops@example.com')
  })

  it('gets critical audit events from the org-scoped event feed', async () => {
    server.use(
      http.get('*/v1/organizations/:orgId/audit-events', () => {
        return HttpResponse.json({
          events: [
            {
              id: 'evt_critical',
              organization_id: 'org_123',
              timestamp: new Date().toISOString(),
              actor_id: 'system',
              actor_type: 'system',
              action: 'flow.execution.failed',
              resource_type: 'flow',
              resource_id: 'flow_1',
              resource_name: 'Issuance flow',
              changes: null,
              metadata: { severity: 'error' },
            },
            {
              id: 'evt_info',
              organization_id: 'org_123',
              timestamp: new Date().toISOString(),
              actor_id: 'system',
              actor_type: 'system',
              action: 'credential.issued',
              resource_type: 'credential',
              resource_id: 'cred_1',
              resource_name: 'Credential cred_1',
              changes: null,
              metadata: { severity: 'info' },
            },
          ],
        })
      })
    )

    const events = await getCriticalEvents('org_123')

    expect(events).toHaveLength(1)
    expect(events[0].id).toBe('evt_critical')
    expect(events[0].type).toBe('flow.execution.failed')
  })

  it('saves a filter view in org-scoped local storage', async () => {
    const organizationId = `org-save-${Date.now()}`
    const view = {
      name: 'Critical Team Events',
      filters: { severity: 'critical', resource_type: 'team' },
    }

    const result = await saveFilterView(organizationId, view)
    const savedViews = await listFilterViews(organizationId)

    expect(result.id).toBeTruthy()
    expect(result.name).toBe('Critical Team Events')
    expect(savedViews).toHaveLength(1)
    expect(savedViews[0].name).toBe('Critical Team Events')
  })

  it('keeps saved filter views scoped to the active organization', async () => {
    const orgA = `org-scope-a-${Date.now()}`
    const orgB = `org-scope-b-${Date.now()}`

    await saveFilterView(orgA, {
      name: 'Critical',
      filters: { severity: 'critical' },
    })
    await saveFilterView(orgB, {
      name: 'Sign-ins',
      filters: { category: 'authentication' },
    })

    const org123Views = await listFilterViews(orgA)
    const org456Views = await listFilterViews(orgB)

    expect(org123Views).toHaveLength(1)
    expect(org123Views[0].name).toBe('Critical')
    expect(org456Views).toHaveLength(1)
    expect(org456Views[0].name).toBe('Sign-ins')
  })
})