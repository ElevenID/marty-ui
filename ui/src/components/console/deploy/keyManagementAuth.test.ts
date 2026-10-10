import { describe, expect, it } from 'vitest'
import { isAuthComplete, isAuthModeAvailable, serializeAuthReference } from './keyManagementAuth'

describe('key management authentication', () => {
  it('uses the service workload identity without sending a credential override', () => {
    for (const mode of ['iam_role', 'workload_identity']) {
      expect(isAuthComplete(mode, {})).toBe(true)
      expect(serializeAuthReference(mode, { token: 'must-not-leak' })).toBe('')
    }
  })

  it('requires complete structured credentials and sends only the chosen mode fields', () => {
    expect(isAuthComplete('access_key', { access_key_id: 'AKIAEXAMPLE' })).toBe(false)
    const values = {
      access_key_id: 'AKIAEXAMPLE', secret_access_key: 'aws-secret',
      session_token: 'session', client_secret: 'stale-azure-secret',
    }
    expect(isAuthComplete('access_key', values)).toBe(true)
    expect(JSON.parse(serializeAuthReference('access_key', values))).toEqual({
      access_key_id: 'AKIAEXAMPLE', secret_access_key: 'aws-secret', session_token: 'session',
    })
    expect(JSON.parse(serializeAuthReference('service_account', { email: 'signer@project.iam.gserviceaccount.com' }))).toEqual({
      email: 'signer@project.iam.gserviceaccount.com',
    })
  })

  it('does not accept modes that the signer cannot use yet', () => {
    for (const mode of ['certificate', 'approle', 'mtls', 'api_key', 'custom', 'service_token']) {
      expect(isAuthModeAvailable(mode)).toBe(false)
      expect(isAuthComplete(mode, { token: 'secret' })).toBe(false)
    }
  })
})
