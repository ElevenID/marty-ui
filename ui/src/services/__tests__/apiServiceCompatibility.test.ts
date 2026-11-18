import { describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'
import { handleApiError, withApiErrorHandling } from '../api'
import { getCredentialMetadata } from '../credentialsApi'
import { getFlow } from '../flowsApi'
import { activateComplianceProfile, suspendComplianceProfile } from '../complianceProfilesApi'
import { getPhysicalDocumentCapabilities } from '../physicalDocumentsApi'
import { getPolicySet } from '../policySetsApi'
import { getVerificationRequest } from '../zkVerificationApi'

describe('shared service error boundary compatibility', () => {
  const reads = [
    ['credentials', '/v1/credentials/credential-1', () => getCredentialMetadata('credential-1')],
    ['flows', '/v1/flows/definitions/flow-1', () => getFlow('flow-1')],
    ['passport', '/v1/passport/capabilities', () => getPhysicalDocumentCapabilities()],
    ['policy sets', '/v1/policy-sets/policy-1', () => getPolicySet('org-1', 'policy-1')],
    ['verification', '/v1/flows/instances/instance-1/request', () => getVerificationRequest('instance-1')],
  ] as const

  it.each(reads)('preserves the HTTP error response for %s', async (_, path, read) => {
    server.use(http.get(`http://localhost:8000${path}`, () =>
      HttpResponse.json({ detail: 'Tenant access denied' }, { status: 403 })))
    await expect(read()).rejects.toMatchObject({
      message: 'Tenant access denied',
      response: { error: { code: 'HTTP_403', message: 'Tenant access denied', recovery_action: 'fail_fast' } },
    })
  })

  it.each([
    ['activate', activateComplianceProfile],
    ['suspend', suspendComplianceProfile],
  ] as const)('returns the direct compliance %s payload with encoded IDs', async (action, changeStatus) => {
    server.use(http.post(`http://localhost:8000/v1/compliance-profiles/profile%2Fone/${action}`, async ({ request }) => {
      expect(await request.json()).toEqual({})
      return HttpResponse.json({ id: 'profile/one', status: action })
    }))
    await expect(changeStatus('profile/one')).resolves.toEqual({ id: 'profile/one', status: action })
  })

  it('retains the legacy normalization of synchronous preparation errors', async () => {
    const error = Object.assign(new Error('Invalid local input'), { code: 'LOCAL_VALIDATION' })
    await expect(withApiErrorHandling(() => { throw error })).rejects.toMatchObject({
      message: handleApiError(error).message,
    })
  })

  it('retains the legacy normalization of asynchronous transport failures', async () => {
    const error = new TypeError('Failed to fetch')
    await expect(withApiErrorHandling(() => Promise.reject(error))).rejects.toMatchObject({
      message: handleApiError(error).message,
    })
  })

  it('preserves an existing HTTP error object and response identity', async () => {
    const error = Object.assign(new Error('Denied'), { response: { status: 403, data: { detail: 'Denied' } } })
    await expect(withApiErrorHandling(() => Promise.reject(error))).rejects.toBe(error)
  })
})
