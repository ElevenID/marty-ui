import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createSubscription, listSubscriptions } from '../subscriptionsApi'

describe('subscriptionsApi', () => {
  it('uses the public gateway contract with organization binding and idempotency', async () => {
    let body: Record<string, unknown> | undefined
    let idempotencyKey: string | null = null
    server.use(
      http.post('http://localhost:8000/v1/subscriptions', async ({ request }) => {
        body = await request.json() as Record<string, unknown>
        idempotencyKey = request.headers.get('Idempotency-Key')
        return HttpResponse.json({ id: 'subscription-1', ...body })
      }),
      http.get('http://localhost:8000/v1/subscriptions', () => (
        HttpResponse.json([{ id: 'subscription-1' }])
      )),
    )

    const created = await createSubscription('org-1', {
      name: 'Admissions approvals',
      eventTypes: ['application.approved'],
      deliveryTargetId: 'webhook-1',
    })
    expect(created.id).toBe('subscription-1')
    expect(body).toMatchObject({
      organization_id: 'org-1',
      delivery_channel: 'WEBHOOK',
      delivery_target_id: 'webhook-1',
      event_types: ['application.approved'],
    })
    expect(String(idempotencyKey)).toContain('v1-subscriptions')
    expect(await listSubscriptions('org-1')).toEqual([{ id: 'subscription-1' }])
  })
})
