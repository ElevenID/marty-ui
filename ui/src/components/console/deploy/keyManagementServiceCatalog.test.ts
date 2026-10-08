import { describe, expect, it } from 'vitest'
import { normalizeKeyManagementConfig } from './keyManagementServiceCatalog'

describe('key management configuration boundary', () => {
  it('does not invent a signing service from obsolete flat HSM settings', () => {
    const normalized = normalizeKeyManagementConfig({
      hsm_enabled: true,
      hsm_settings: {
        service_url: 'https://obsolete.example.test',
        key_reference: 'obsolete-key',
      },
    })

    expect(normalized.services).toEqual([])
    expect(normalized.default_service_id).toBeNull()
    expect(normalized).not.toHaveProperty('hsm_settings')
  })

  it('keeps a registered remote service and its default selection', () => {
    const normalized = normalizeKeyManagementConfig({
      services: [{
        id: 'remote-signer',
        service_type: 'openbao-transit',
        key_reference: 'issuer-key-v4',
      }],
      default_service_id: 'remote-signer',
    })

    expect(normalized.services[0].key_reference).toBe('issuer-key-v4')
    expect(normalized.default_service_id).toBe('remote-signer')
  })
})
