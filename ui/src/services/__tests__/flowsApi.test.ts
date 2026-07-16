import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'

import { createFlow, getFlowInstance, listFlowInstances, listFlows } from '../flowsApi'

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

  it('lists organization-wide runtime instances without one request per flow', async () => {
    let requestUrl = ''
    server.use(
      http.get('http://localhost:8000/v1/flows/instances', ({ request }) => {
        requestUrl = request.url
        return HttpResponse.json([{ id: 'instance-1', flow_id: 'flow-1' }])
      })
    )

    const result = await listFlowInstances({ organization_id: 'org-123', status: 'pending', limit: 50 })

    expect(result).toHaveLength(1)
    expect(requestUrl).toContain('organization_id=org-123')
    expect(requestUrl).toContain('status=pending')
    expect(requestUrl).toContain('limit=50')
  })

  it('requires direct arrays for flow definition and instance lists', async () => {
    server.use(
      http.get('http://localhost:8000/v1/flows/definitions', () => HttpResponse.json({ items: [] })),
      http.get('http://localhost:8000/v1/flows/instances', () => HttpResponse.json({ instances: [] })),
    )

    await expect(listFlows({ organization_id: 'org-123' })).rejects.toThrow(/malformed list response/i)
    await expect(listFlowInstances({ organization_id: 'org-123' })).rejects.toThrow(/malformed list response/i)
  })

  it('loads one runtime instance by stable instance ID', async () => {
    server.use(
      http.get('http://localhost:8000/v1/flows/instances/instance-1', () => (
        HttpResponse.json({ id: 'instance-1', status: 'pending' })
      ))
    )

    await expect(getFlowInstance('instance-1')).resolves.toMatchObject({ id: 'instance-1' })
  })
})
