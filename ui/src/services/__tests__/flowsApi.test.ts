import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createFlow } from '../flowsApi'

describe('flowsApi', () => {
  it('creates flows with organization context and an idempotency key', async () => {
    let requestBody: any
    let idempotencyKey: string | null = null

    server.use(
      http.post('http://localhost:8000/v1/flows/definitions', async ({ request }) => {
        idempotencyKey = request.headers.get('Idempotency-Key')
        requestBody = await request.json()
        return HttpResponse.json({
          id: 'flow-1',
          ...requestBody,
          status: 'draft',
        })
      })
    )

    const result = await createFlow({
      organization_id: 'org-123',
      name: 'Employee badge issuance',
      flow_type: 'oid4vci_pre_authorized',
      deployment_profile_id: 'deploy-1',
      credential_template_id: 'template-1',
    })

    expect(String(idempotencyKey)).toContain('v1-flows-definitions')
    expect(requestBody.organization_id).toBe('org-123')
    expect(result.id).toBe('flow-1')
  })

  it('trims organization context before creating a flow', async () => {
    let requestBody: any

    server.use(
      http.post('http://localhost:8000/v1/flows/definitions', async ({ request }) => {
        requestBody = await request.json()
        return HttpResponse.json({
          id: 'flow-1',
          ...requestBody,
          status: 'draft',
        })
      })
    )

    await createFlow({
      organization_id: ' org-123 ',
      name: 'Employee badge issuance',
      flow_type: 'oid4vci_pre_authorized',
      deployment_profile_id: 'deploy-1',
      credential_template_id: 'template-1',
    })

    expect(requestBody.organization_id).toBe('org-123')
  })

  it('preserves operation status unknown when retry cannot confirm flow creation', async () => {
    const idempotencyKeys: string[] = []
    let attempts = 0

    server.use(
      http.post('http://localhost:8000/v1/flows/definitions', ({ request }) => {
        attempts += 1
        idempotencyKeys.push(String(request.headers.get('Idempotency-Key')))
        return HttpResponse.error()
      })
    )

    await expect(createFlow({
      organization_id: 'org-123',
      name: 'Employee badge issuance',
      flow_type: 'oid4vci_pre_authorized',
      deployment_profile_id: 'deploy-1',
      credential_template_id: 'template-1',
    })).rejects.toMatchObject({
      operationStatusUnknown: true,
      idempotencyKey: expect.stringContaining('v1-flows-definitions'),
    })

    expect(attempts).toBe(2)
    expect(idempotencyKeys[0]).toBe(idempotencyKeys[1])
  })
})
