import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  listNotifications,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  getNotificationPreferences,
  updateNotificationPreferences,
  listAlertRules,
  createAlertRule,
  updateAlertRule,
  deleteAlertRule,
  toggleAlertRule,
} from '../notificationsApi'

describe('notificationsApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('applies supported filters when listing notifications', async () => {
    let queryParams: URLSearchParams | undefined

    server.use(
      http.get('*/v1/notifications', ({ request }) => {
        queryParams = new URL(request.url).searchParams
        return HttpResponse.json({ notifications: [], total: 0 })
      })
    )

    await listNotifications({
      unread_only: true,
      severity: 'error',
      limit: 20,
      offset: 40,
    })

    expect(queryParams?.get('unread_only')).toBe('true')
    expect(queryParams?.get('severity')).toBe('error')
    expect(queryParams?.get('limit')).toBe('20')
    expect(queryParams?.get('offset')).toBe('40')
  })

  it('gets the unread count', async () => {
    server.use(
      http.get('*/v1/notifications/unread/count', () => {
        return HttpResponse.json({ unread: 7 })
      })
    )

    const result = await getUnreadCount()

    expect(result.unread).toBe(7)
  })

  it('marks a single notification as read', async () => {
    let notificationId: string | undefined

    server.use(
      http.patch('*/v1/notifications/:notificationId/read', ({ params }) => {
        notificationId = params.notificationId as string
        return HttpResponse.json({ ok: true })
      })
    )

    await markAsRead('notif_123')

    expect(notificationId).toBe('notif_123')
  })

  it('marks all notifications as read', async () => {
    let method: string | undefined

    server.use(
      http.post('*/v1/notifications/read-all', ({ request }) => {
        method = request.method
        return HttpResponse.json({ ok: true })
      })
    )

    await markAllAsRead()

    expect(method).toBe('POST')
  })

  it('deletes a notification by id', async () => {
    let notificationId: string | undefined

    server.use(
      http.delete('*/v1/notifications/:notificationId', ({ params }) => {
        notificationId = params.notificationId as string
        return HttpResponse.json({ ok: true })
      })
    )

    await deleteNotification('notif_456')

    expect(notificationId).toBe('notif_456')
  })

  it('gets notification preferences', async () => {
    server.use(
      http.get('*/v1/notifications/preferences', () => {
        return HttpResponse.json({
          email_on_errors: true,
          email_on_warnings: false,
          daily_summary: true,
        })
      })
    )

    const preferences = await getNotificationPreferences()

    expect(preferences.email_on_errors).toBe(true)
    expect(preferences.daily_summary).toBe(true)
  })

  it('updates notification preferences', async () => {
    const updates = {
      email_on_errors: true,
      email_on_warnings: true,
      daily_summary: false,
      webhook_url: 'https://example.com/webhooks/alerts',
    }
    let receivedBody: any

    server.use(
      http.patch('*/v1/notifications/preferences', async ({ request }) => {
        receivedBody = await request.json()
        return HttpResponse.json(receivedBody)
      })
    )

    const result = await updateNotificationPreferences(updates)

    expect(receivedBody).toEqual(updates)
    expect(result.webhook_url).toBe('https://example.com/webhooks/alerts')
  })

  it('lists alert rules', async () => {
    server.use(
      http.get('*/v1/notifications/rules', () => {
        return HttpResponse.json([
          { id: 'rule_1', name: 'High Error Rate', enabled: true },
        ])
      })
    )

    const rules = await listAlertRules()

    expect(rules).toHaveLength(1)
    expect(rules[0].id).toBe('rule_1')
  })

  it('creates an alert rule', async () => {
    const rule = {
      name: 'Failed Login Rate',
      metric: 'login.failed',
      condition: 'threshold',
      threshold: 5,
      time_window: 15,
      actions: ['email'],
      enabled: true,
    }
    let receivedBody: any

    server.use(
      http.post('*/v1/notifications/rules', async ({ request }) => {
        receivedBody = await request.json()
        return HttpResponse.json({ id: 'rule_new', ...receivedBody }, { status: 201 })
      })
    )

    const result = await createAlertRule(rule)

    expect(receivedBody).toEqual(rule)
    expect(result.id).toBe('rule_new')
  })

  it('updates an alert rule', async () => {
    const updates = { threshold: 10, time_window: 30 }
    let ruleId: string | undefined
    let receivedBody: any

    server.use(
      http.patch('*/v1/notifications/rules/:ruleId', async ({ params, request }) => {
        ruleId = params.ruleId as string
        receivedBody = await request.json()
        return HttpResponse.json({ id: ruleId, ...receivedBody })
      })
    )

    const result = await updateAlertRule('rule_1', updates)

    expect(ruleId).toBe('rule_1')
    expect(receivedBody).toEqual(updates)
    expect(result.threshold).toBe(10)
  })

  it('toggles an alert rule enabled state', async () => {
    let ruleId: string | undefined
    let receivedBody: any

    server.use(
      http.patch('*/v1/notifications/rules/:ruleId', async ({ params, request }) => {
        ruleId = params.ruleId as string
        receivedBody = await request.json()
        return HttpResponse.json({ id: ruleId, ...receivedBody })
      })
    )

    const result = await toggleAlertRule('rule_2', false)

    expect(ruleId).toBe('rule_2')
    expect(receivedBody).toEqual({ enabled: false })
    expect(result.enabled).toBe(false)
  })

  it('deletes an alert rule', async () => {
    let ruleId: string | undefined

    server.use(
      http.delete('*/v1/notifications/rules/:ruleId', ({ params }) => {
        ruleId = params.ruleId as string
        return HttpResponse.json({ ok: true })
      })
    )

    await deleteAlertRule('rule_3')

    expect(ruleId).toBe('rule_3')
  })
})