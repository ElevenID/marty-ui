import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createDeliveryDestination } from '../deliveryDestinationsApi'

describe('deliveryDestinationsApi', () => {
  it('creates delivery destinations with org context and an idempotency key', async () => {
    let requestBody: Record<string, unknown> | undefined
    let idempotencyKey: string | null = null

    server.use(
      http.post('http://localhost:8000/v1/delivery-destinations', async ({ request }) => {
        idempotencyKey = request.headers.get('Idempotency-Key')
        requestBody = await request.json() as Record<string, unknown>
        return HttpResponse.json({ id: 'destination-1', ...requestBody }, { status: 201 })
      }),
    )

    const result = await createDeliveryDestination({
      organization_id: ' org-123 ',
      name: 'Canvas Credentials',
      provider: 'canvas_credentials',
      mode: 'organization_mirror',
    })

    expect(String(idempotencyKey)).toContain('v1-delivery-destinations')
    expect(requestBody?.organization_id).toBe('org-123')
    expect(result.id).toBe('destination-1')
  })
})
