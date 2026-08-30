import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import {
  createWebhook,
  deleteWebhook,
  getAvailableEventTypes,
  getWebhookDeliveryAttempts,
  regenerateWebhookSecret,
  updateWebhook,
} from '../webhooksApi'

describe('webhooksApi', () => {
  it('creates webhooks with org context and an idempotency key', async () => {
    let requestBody: Record<string, unknown> | undefined
    let idempotencyKey: string | null = null

    server.use(
      http.post('http://localhost:8000/v1/webhooks', async ({ request }) => {
        idempotencyKey = request.headers.get('Idempotency-Key')
        requestBody = await request.json() as Record<string, unknown>
        return HttpResponse.json({ id: 'webhook-1', ...requestBody }, { status: 201 })
      }),
    )

    const result = await createWebhook(' org-123 ', {
      name: 'Partner callback',
      url: 'https://partner.example.com/marty/events',
      eventTypes: ['credential.issued'],
      description: 'Production callback',
    })

    expect(String(idempotencyKey)).toContain('v1-webhooks')
    expect(requestBody?.organization_id).toBe('org-123')
    expect(requestBody?.name).toBe('Partner callback')
    expect(result.id).toBe('webhook-1')
  })

  it('binds webhook mutations to the selected organization', async () => {
    const requests: string[] = []

    server.use(
      http.patch('http://localhost:8000/v1/webhooks/webhook-1', ({ request }) => {
        requests.push(request.url)
        return HttpResponse.json({ id: 'webhook-1', organization_id: 'org-123' })
      }),
      http.delete('http://localhost:8000/v1/webhooks/webhook-1', ({ request }) => {
        requests.push(request.url)
        return HttpResponse.json({ success: true })
      }),
    )

    await updateWebhook(' org-123 ', 'webhook-1', {
      description: 'Updated callback',
    })
    await deleteWebhook('org-123', 'webhook-1')

    expect(requests).toHaveLength(2)
    for (const requestUrl of requests) {
      expect(new URL(requestUrl).searchParams.get('organization_id')).toBe('org-123')
    }
  })

  it('normalizes backend webhook fields, delivery arrays, rotation, and supported events', async () => {
    server.use(
      http.get('http://localhost:8000/v1/webhooks/webhook-1/deliveries', () => (
        HttpResponse.json([{
          id: 'delivery-1',
          correlation_id: '11111111-1111-4111-8111-111111111111',
        }])
      )),
      http.post('http://localhost:8000/v1/webhooks/webhook-1/regenerate-secret', () => (
        HttpResponse.json({ id: 'webhook-1', endpoint_url: 'https://partner.example/hook', signing_secret: 'rotated' })
      )),
      http.get('http://localhost:8000/v1/webhooks/event-types', () => (
        HttpResponse.json({ event_types: ['application.approved', 'credential.issued'] })
      )),
    )

    expect(await getWebhookDeliveryAttempts('org-123', 'webhook-1')).toEqual([{
      id: 'delivery-1',
      correlation_id: '11111111-1111-4111-8111-111111111111',
    }])
    expect((await regenerateWebhookSecret('org-123', 'webhook-1')).secret).toBe('rotated')
    expect((await getAvailableEventTypes()).categories).toEqual([
      { name: 'Application', events: [{ type: 'application.approved', description: 'application approved' }] },
      { name: 'Credential', events: [{ type: 'credential.issued', description: 'credential issued' }] },
    ])
  })
})
