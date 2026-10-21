import { describe, expect, it } from 'vitest'
import { KEY_MANAGEMENT_PURPOSES, createKeyManagementServicePayload, getCompatiblePurposesForAlgorithm, normalizeKeyManagementConfig } from './keyManagementServiceCatalog'

describe('key management configuration boundary', () => {
  it('exposes the native OID4VP request purpose only for its required ES256 key', () => {
    expect(KEY_MANAGEMENT_PURPOSES.find((purpose) => purpose.value === 'oid4vp_request_signing')?.formats)
      .toEqual(['oauth-authz-req+jwt'])
    expect(getCompatiblePurposesForAlgorithm('ES256')).toContain('oid4vp_request_signing')
    for (const algorithm of ['ES384', 'ES512', 'RS256', 'EdDSA']) {
      expect(getCompatiblePurposesForAlgorithm(algorithm)).not.toContain('oid4vp_request_signing')
    }
  })

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


it('preserves existing transit CA trust through config normalization and new registration payloads', () => {
  const normalized = normalizeKeyManagementConfig({
    services: [{ id: 'external-transit', service_type: 'openbao-transit', ca_cert_file: '/run/secrets/customer-ca' }],
    service_type_catalog: [{ id: 'openbao-transit', protocol: 'vault-transit', connection_fields: ['endpoint', 'mount'] }],
  })
  expect(normalized.services[0].ca_cert_file).toBe('/run/secrets/customer-ca')
  expect(normalizeKeyManagementConfig(normalized).services[0].ca_cert_file).toBe('/run/secrets/customer-ca')
  expect(normalized.service_type_catalog[0].connection_fields).toContain('ca_cert_file')
  expect(createKeyManagementServicePayload({ service_type: 'openbao-transit', ca_cert_file: '/run/secrets/new-ca' },
    normalized.service_type_catalog).ca_cert_file).toBe('/run/secrets/new-ca')
  expect(createKeyManagementServicePayload({ service_type: 'openbao-transit' }, normalized.service_type_catalog).ca_cert_file).toBe('')
})
