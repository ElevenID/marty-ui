import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import {
  createCanvasIntegrationSecret,
  createCanvasPlatform,
  createCanvasProgramBinding,
} from '../canvasIntegrationsApi'

describe('canvasIntegrationsApi', () => {
  it('creates Canvas artifacts with org context and idempotency keys', async () => {
    const seen: Array<{ path: string; organizationId: string; idempotencyKey: string | null }> = []

    server.use(
      http.post('http://localhost:8000/v1/integrations/canvas/platforms', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({
          path: '/platforms',
          organizationId: String(body.organization_id),
          idempotencyKey: request.headers.get('Idempotency-Key'),
        })
        return HttpResponse.json({ id: 'platform-1', ...body }, { status: 201 })
      }),
      http.post('http://localhost:8000/v1/integrations/canvas/platforms/platform-1/program-bindings', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({
          path: '/program-bindings',
          organizationId: String(body.organization_id),
          idempotencyKey: request.headers.get('Idempotency-Key'),
        })
        return HttpResponse.json({ id: 'binding-1', ...body }, { status: 201 })
      }),
      http.post('http://localhost:8000/v1/integrations/canvas/integration-secrets', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>
        seen.push({
          path: '/integration-secrets',
          organizationId: String(body.organization_id),
          idempotencyKey: request.headers.get('Idempotency-Key'),
        })
        return HttpResponse.json({ id: 'secret-1', ...body }, { status: 201 })
      }),
    )

    await createCanvasPlatform({ organization_id: ' org-123 ', name: 'Canvas' })
    await createCanvasProgramBinding('platform-1', {
      organization_id: ' org-123 ',
      display_name: 'Course',
    })
    await createCanvasIntegrationSecret({
      organization_id: ' org-123 ',
      provider: 'canvas_credentials',
      secret_name: 'CANVAS_TOKEN',
    })

    expect(seen).toEqual([
      expect.objectContaining({
        path: '/platforms',
        organizationId: 'org-123',
        idempotencyKey: expect.stringContaining('v1-integrations-canvas-platforms'),
      }),
      expect.objectContaining({
        path: '/program-bindings',
        organizationId: 'org-123',
        idempotencyKey: expect.stringContaining('v1-integrations-canvas-platforms-platform-1-program-bindings'),
      }),
      expect.objectContaining({
        path: '/integration-secrets',
        organizationId: 'org-123',
        idempotencyKey: expect.stringContaining('v1-integrations-canvas-integration-secrets'),
      }),
    ])
  })
})
