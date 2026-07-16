import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createComplianceProfile, listComplianceProfiles } from '../complianceProfilesApi'

describe('complianceProfilesApi', () => {
  it('creates compliance profiles with explicit idempotency and trimmed organization context', async () => {
    let requestBody: Record<string, unknown> | undefined
    let idempotencyKey: string | null = null

    server.use(
      http.post('http://localhost:8000/v1/compliance-profiles', async ({ request }) => {
        idempotencyKey = request.headers.get('Idempotency-Key')
        requestBody = await request.json() as Record<string, unknown>
        return HttpResponse.json({
          id: 'compliance-1',
          ...requestBody,
        }, { status: 201 })
      })
    )

    const result = await createComplianceProfile({
      organization_id: ' org-123 ',
      name: 'Enterprise VC Baseline',
      compliance_code: 'ENTERPRISE_VC',
    })

    expect(String(idempotencyKey)).toContain('v1-compliance-profiles')
    expect(requestBody?.organization_id).toBe('org-123')
    expect(result.id).toBe('compliance-1')
  })

  it('lists compliance profiles with explicit organization_id', async () => {
    let requestUrl: URL | undefined

    server.use(
      http.get('http://localhost:8000/v1/compliance-profiles', ({ request }) => {
        requestUrl = new URL(request.url)
        return HttpResponse.json([
          {
            id: 'compliance-1',
            organization_id: 'org-123',
            name: 'Enterprise VC Baseline',
            compliance_code: 'ENTERPRISE_VC',
            discoverable: true,
          },
        ])
      })
    )

    const result = await listComplianceProfiles({ organization_id: 'org-123' })

    expect(requestUrl?.searchParams.get('organization_id')).toBe('org-123')
    expect(result).toHaveLength(1)
  })

  it('trims organization_id before listing compliance profiles', async () => {
    let requestUrl: URL | undefined

    server.use(
      http.get('http://localhost:8000/v1/compliance-profiles', ({ request }) => {
        requestUrl = new URL(request.url)
        return HttpResponse.json([])
      })
    )

    await listComplianceProfiles({ organization_id: ' org-123 ' })

    expect(requestUrl?.searchParams.get('organization_id')).toBe('org-123')
  })

  it('fails locally before sending unscoped list requests', async () => {
    let requested = false

    server.use(
      http.get('http://localhost:8000/v1/compliance-profiles', () => {
        requested = true
        return HttpResponse.json([])
      })
    )

    await expect(listComplianceProfiles()).rejects.toMatchObject({
      code: 'ORG_REQUIRED',
      status: 400,
    })
    expect(requested).toBe(false)
  })
})
