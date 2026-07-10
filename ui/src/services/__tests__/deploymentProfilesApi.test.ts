import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createDeploymentProfile, listDeploymentProfiles } from '../deploymentProfilesApi'

describe('deploymentProfilesApi', () => {
  it('creates deployment profiles with a trimmed organization context and idempotency key', async () => {
    let requestBody: any
    let idempotencyKey: string | null = null

    server.use(
      http.post('http://localhost:8000/v1/deployment-profiles', async ({ request }) => {
        idempotencyKey = request.headers.get('Idempotency-Key')
        requestBody = await request.json()
        return HttpResponse.json({
          id: 'deployment-1',
          ...requestBody,
          status: 'active',
        }, { status: 201 })
      })
    )

    const result = await createDeploymentProfile({
      organization_id: ' org-123 ',
      name: 'Production issuance',
      trust_profile_id: 'trust-1',
      credential_template_ids: ['template-1'],
      presentation_policy_ids: ['policy-1'],
      network_mode: 'ONLINE',
      environment_config: {},
    })

    expect(String(idempotencyKey)).toContain('v1-deployment-profiles')
    expect(requestBody.organization_id).toBe('org-123')
    expect(result.id).toBe('deployment-1')
  })

  it('lists deployment profiles with a trimmed organization context', async () => {
    let requestUrl: URL | undefined

    server.use(
      http.get('http://localhost:8000/v1/deployment-profiles', ({ request }) => {
        requestUrl = new URL(request.url)
        return HttpResponse.json([])
      })
    )

    await listDeploymentProfiles({ organization_id: ' org-123 ' })

    expect(requestUrl?.searchParams.get('organization_id')).toBe('org-123')
  })

  it('fails locally when organization context is missing', async () => {
    let requested = false

    server.use(
      http.get('http://localhost:8000/v1/deployment-profiles', () => {
        requested = true
        return HttpResponse.json([])
      }),
      http.post('http://localhost:8000/v1/deployment-profiles', () => {
        requested = true
        return HttpResponse.json({})
      })
    )

    await expect(listDeploymentProfiles({ organization_id: 'null' })).rejects.toMatchObject({
      code: 'ORG_REQUIRED',
      status: 400,
    })
    await expect(createDeploymentProfile({ name: 'Missing org' })).rejects.toMatchObject({
      code: 'ORG_REQUIRED',
      status: 400,
    })
    expect(requested).toBe(false)
  })
})
