import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import {
  createApiKey,
  deleteApiKey,
  listApiKeys,
  revokeApiKey,
} from '../apiKeysApi'

describe('apiKeysApi', () => {
  it('lists api keys through the gateway top-level route with organization_id', async () => {
    let requestUrl: URL | undefined

    server.use(
      http.get('http://localhost:8000/v1/api-keys', ({ request }) => {
        requestUrl = new URL(request.url)
        return HttpResponse.json([
          {
            id: 'key-1',
            name: 'Partner',
            key_prefix: 'pk_live_',
            scopes: ['flows:execute'],
            status: 'active',
            created_at: '2026-07-08T00:00:00Z',
          },
        ])
      })
    )

    const result = await listApiKeys('org-123')

    expect(requestUrl?.pathname).toBe('/v1/api-keys')
    expect(requestUrl?.searchParams.get('organization_id')).toBe('org-123')
    expect(result).toHaveLength(1)
  })

  it('trims organization_id before sending api-key requests', async () => {
    let requestUrl: URL | undefined

    server.use(
      http.get('http://localhost:8000/v1/api-keys', ({ request }) => {
        requestUrl = new URL(request.url)
        return HttpResponse.json([])
      })
    )

    await listApiKeys(' org-123 ')

    expect(requestUrl?.searchParams.get('organization_id')).toBe('org-123')
  })

  it('creates api keys through the gateway top-level route with organization_id', async () => {
    let requestUrl: URL | undefined
    let requestBody: any
    let idempotencyKey: string | null = null

    server.use(
      http.post('http://localhost:8000/v1/api-keys', async ({ request }) => {
        requestUrl = new URL(request.url)
        idempotencyKey = request.headers.get('Idempotency-Key')
        requestBody = await request.json()
        return HttpResponse.json({
          id: 'key-new',
          name: requestBody.name,
          key: 'pk_live_secret',
          key_prefix: 'pk_live_',
          scopes: requestBody.scopes,
          status: 'active',
          created_at: '2026-07-08T00:00:00Z',
        })
      })
    )

    const result = await createApiKey('org-123', {
      name: 'Partner',
      scopes: ['flows:execute'],
    })

    expect(requestUrl?.pathname).toBe('/v1/api-keys')
    expect(requestUrl?.searchParams.get('organization_id')).toBe('org-123')
    expect(String(idempotencyKey)).toContain('v1-api-keys')
    expect(requestBody).toMatchObject({
      name: 'Partner',
      scopes: ['flows:execute'],
    })
    expect(result.key).toBe('pk_live_secret')
  })

  it('revokes and deletes api keys through the gateway delete route', async () => {
    const seenUrls: string[] = []

    server.use(
      http.delete('http://localhost:8000/v1/api-keys/:keyId', ({ request, params }) => {
        seenUrls.push(`${params.keyId}:${new URL(request.url).searchParams.get('organization_id')}`)
        return HttpResponse.json({ success: true })
      })
    )

    await revokeApiKey('org-123', 'key-1')
    await deleteApiKey('org-456', 'key-2')

    expect(seenUrls).toEqual(['key-1:org-123', 'key-2:org-456'])
  })

  it('fails locally without sending api-key requests when organization_id is missing', async () => {
    let requested = false

    server.use(
      http.get('http://localhost:8000/v1/api-keys', () => {
        requested = true
        return HttpResponse.json([])
      }),
      http.post('http://localhost:8000/v1/api-keys', () => {
        requested = true
        return HttpResponse.json({})
      })
    )

    await expect(listApiKeys(null as unknown as string)).rejects.toMatchObject({
      code: 'ORG_REQUIRED',
      status: 400,
    })
    await expect(createApiKey('null', { name: 'Bad', scopes: ['flows:execute'] })).rejects.toMatchObject({
      code: 'ORG_REQUIRED',
      status: 400,
    })
    expect(requested).toBe(false)
  })
})
