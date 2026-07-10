import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createWebhook } from '../webhooksApi'

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
      url: 'https://partner.example.com/marty/events',
      eventTypes: ['credential.issued'],
      description: 'Production callback',
    })

    expect(String(idempotencyKey)).toContain('v1-webhooks')
    expect(requestBody?.organization_id).toBe('org-123')
    expect(result.id).toBe('webhook-1')
  })
})
