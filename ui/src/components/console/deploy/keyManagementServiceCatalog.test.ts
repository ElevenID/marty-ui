import { describe, expect, it } from 'vitest'
import { normalizeKeyManagementConfig } from './keyManagementServiceCatalog'

describe('key management configuration boundary', () => {
  it('advertises only authentication modes supported by native signers', () => {
    const catalog = normalizeKeyManagementConfig({}).service_type_catalog
    expect(catalog.find((service) => service.id === 'openbao-transit')?.auth_modes).toEqual(['token'])
    expect(catalog.find((service) => service.id === 'azure-key-vault')?.auth_modes).toEqual([
      'managed_identity', 'client_secret',
    ])
    expect(catalog.find((service) => service.id === 'custom-transit-compatible')?.auth_modes).toEqual(['token'])
  })

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
