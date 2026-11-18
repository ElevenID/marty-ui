import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'
import { activatePolicySet, archivePolicySet, createPolicySet, getPolicySet, listPolicySets, listPolicySetTemplates, updatePolicySetMetadata, validatePolicySet } from '../policySetsApi'

describe('public organization-scoped Policy Set client', () => {
  it('uses canonical scoped reads, validation, creation and lifecycle bodies', async () => {
    const requests: any[] = []
    server.use(http.all('http://localhost:8000/v1/policy-sets*', async ({ request }) => {
      requests.push({ path: new URL(request.url).pathname, organization: new URL(request.url).searchParams.get('organization_id'), method: request.method,
        body: request.method === 'GET' ? undefined : await request.json() })
      return HttpResponse.json({ id: 'set-1' })
    }))
    await listPolicySets(' org-1 ', 'DRAFT'); await listPolicySetTemplates('org-1'); await getPolicySet('org-1', 'set/1')
    await validatePolicySet('org-1', [{ policy_id: 'read', cedar_text: 'permit;' }])
    await createPolicySet('org-1', { name: 'Draft', cedar_policies: [] })
    await activatePolicySet('org-1', 'set-1'); await archivePolicySet('org-1', 'set-1')
    expect(requests.every(x => x.organization === 'org-1')).toBe(true)
    expect(requests.map(x => x.path)).toEqual(['/v1/policy-sets', '/v1/policy-sets/templates', '/v1/policy-sets/set%2F1', '/v1/policy-sets/validate', '/v1/policy-sets', '/v1/policy-sets/set-1/activate', '/v1/policy-sets/set-1/archive'])
    expect(requests[3].body).toEqual({ cedar_policies: [{ policy_id: 'read', cedar_text: 'permit;' }] })
    expect(requests[4].body).toEqual({ name: 'Draft', cedar_policies: [] })
    expect(requests.slice(5).map(x => x.body)).toEqual([null, null])
  })

  it('serializes only explicit metadata and retains nullable clear semantics', async () => {
    let payload: any
    server.use(http.patch('*/v1/policy-sets/set-1', async ({ request }) => {
      expect(new URL(request.url).searchParams.get('organization_id')).toBe('org-1')
      payload = await request.json(); return HttpResponse.json({ id: 'set-1' })
    }))
    await updatePolicySetMetadata('org-1', 'set-1', { description: null })
    expect(payload).toEqual({ description: null })
    await updatePolicySetMetadata('org-1', 'set-1', { name: 'Renamed' })
    expect(payload).toEqual({ name: 'Renamed' })
    await expect(updatePolicySetMetadata('org-1', 'set-1', { cedar_policies: [] })).rejects.toThrow()
    await expect(updatePolicySetMetadata('org-1', 'set-1', {})).rejects.toThrow()
  })

  it('rejects missing organization context for every operation before sending', async () => {
    for (const operation of [() => listPolicySets(''), () => listPolicySetTemplates(''), () => getPolicySet('', 'set-1'), () => validatePolicySet('', []),
      () => createPolicySet('', {}), () => updatePolicySetMetadata('', 'set-1', { name: 'Draft' }), () => activatePolicySet('', 'set-1'), () => archivePolicySet('', 'set-1')]) {
      await expect(operation()).rejects.toThrow()
    }
  })
})
