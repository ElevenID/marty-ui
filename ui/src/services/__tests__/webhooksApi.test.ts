import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import {
  createWebhook,
  createWebhookConfiguration,
  deleteWebhook,
  getAvailableEventTypes,
  getWebhookDeliveryAttempts,
  regenerateWebhookSecret,
  updateWebhook,
  updateWebhookConfiguration,
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

  it('creates a usable endpoint and delivery subscription as one UI operation', async () => {
    let subscriptionBody: Record<string, unknown> | undefined
    server.use(
      http.post('http://localhost:8000/v1/webhooks', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        return HttpResponse.json({ id: 'webhook-1', ...body })
      }),
      http.post('http://localhost:8000/v1/subscriptions', async ({ request }) => {
        subscriptionBody = await request.json() as Record<string, unknown>
        return HttpResponse.json({ id: 'subscription-1', ...subscriptionBody })
      }),
    )

    const result = await createWebhookConfiguration('org-123', {
      name: 'Admissions callback',
      url: 'https://partner.example/events',
      description: 'Approval outcomes',
      eventTypes: ['application.*'],
    })

    expect(result.subscription_id).toBe('subscription-1')
    expect(subscriptionBody).toMatchObject({
      organization_id: 'org-123',
      delivery_target_id: 'webhook-1',
      event_types: ['application.*'],
    })
  })

  it('removes an inert endpoint when subscription creation fails', async () => {
    let deleted = false
    server.use(
      http.post('http://localhost:8000/v1/webhooks', () => (
        HttpResponse.json({ id: 'webhook-orphan', name: 'Callback', url: 'https://partner.example/events' })
      )),
      http.post('http://localhost:8000/v1/subscriptions', () => (
        HttpResponse.json({ detail: 'subscription unavailable' }, { status: 503 })
      )),
      http.delete('http://localhost:8000/v1/webhooks/webhook-orphan', () => {
        deleted = true
        return HttpResponse.json({ success: true })
      }),
    )

    await expect(createWebhookConfiguration('org-123', {
      name: 'Callback',
      url: 'https://partner.example/events',
      eventTypes: ['application.approved'],
    })).rejects.toThrow()
    expect(deleted).toBe(true)
  })

  it('preserves both the subscription and cleanup failures when compensation fails', async () => {
    server.use(
      http.post('http://localhost:8000/v1/webhooks', () => (
        HttpResponse.json({ id: 'webhook-orphan', name: 'Callback', url: 'https://partner.example/events' })
      )),
      http.post('http://localhost:8000/v1/subscriptions', () => (
        HttpResponse.json({ detail: 'subscription unavailable' }, { status: 503 })
      )),
      http.delete('http://localhost:8000/v1/webhooks/webhook-orphan', () => (
        HttpResponse.json({ detail: 'cleanup unavailable' }, { status: 503 })
      )),
    )

    let failure: unknown
    try {
      await createWebhookConfiguration('org-123', {
        name: 'Callback',
        url: 'https://partner.example/events',
        eventTypes: ['application.approved'],
      })
    } catch (error) {
      failure = error
    }

    expect(failure).toBeInstanceOf(AggregateError)
    const aggregate = failure as AggregateError
    expect(aggregate.errors).toHaveLength(2)
    expect(aggregate.cause).toBe(aggregate.errors[1])
    expect(aggregate.message).toContain('manual cleanup')
  })

  it('preserves both the subscription and rollback failures when an update cannot compensate', async () => {
    let endpointUpdates = 0
    server.use(
      http.get('http://localhost:8000/v1/webhooks/webhook-1', () => (
        HttpResponse.json({
          id: 'webhook-1',
          name: 'Original',
          url: 'https://partner.example/original',
          event_types: ['application.approved'],
          enabled: true,
        })
      )),
      http.get('http://localhost:8000/v1/subscriptions', () => (
        HttpResponse.json({ subscriptions: [{
          id: 'subscription-1',
          delivery_target_id: 'webhook-1',
        }] })
      )),
      http.patch('http://localhost:8000/v1/webhooks/webhook-1', async ({ request }) => {
        endpointUpdates += 1
        if (endpointUpdates > 1) {
          return HttpResponse.json({ detail: 'rollback unavailable' }, { status: 503 })
        }
        return HttpResponse.json({
          id: 'webhook-1',
          name: 'Updated',
          url: 'https://partner.example/updated',
          event_types: ['credential.issued'],
          enabled: true,
          ...await request.json() as Record<string, unknown>,
        })
      }),
      http.patch('http://localhost:8000/v1/subscriptions/subscription-1', () => (
        HttpResponse.json({ detail: 'subscription unavailable' }, { status: 503 })
      )),
    )

    let failure: unknown
    try {
      await updateWebhookConfiguration('org-123', 'webhook-1', {
        url: 'https://partner.example/updated',
        eventTypes: ['credential.issued'],
      })
    } catch (error) {
      failure = error
    }

    expect(endpointUpdates).toBe(2)
    expect(failure).toBeInstanceOf(AggregateError)
    const aggregate = failure as AggregateError
    expect(aggregate.errors).toHaveLength(2)
    expect(aggregate.cause).toBe(aggregate.errors[1])
    expect(aggregate.message).toContain('manual rollback')
  })
})
