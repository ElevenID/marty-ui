import { describe, expect, it } from 'vitest'
import { KEY_MANAGEMENT_PURPOSES, createKeyManagementServicePayload, createKeyManagementRegistrationPayload, createKeyManagementConfigUpdate, createKeyManagementRemovalPayload, getCompatiblePurposesForAlgorithm, normalizeKeyManagementConfig } from './keyManagementServiceCatalog'

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


it('registration preserves explicit maps and authorizes only the selected key and declared purposes', () => {
  const original = {
    services: [{id:'previous', service_type:'openbao-transit', key_reference:'reserved-key'}],
    default_service_id:'previous',
    key_reference_purposes:{previous:{'reserved-key':['lti_tool_signing']}},
    type_defaults:{lti_tool_signing:'previous'}, format_defaults:{'jwt':'previous'},
  }
  const snapshot = structuredClone(original)
  const next = createKeyManagementServicePayload({id:'new-service',service_type:'openbao-transit',
    key_reference:'selected-key',key_aliases:'unselected-alias',algorithms:['ES256'],
    key_purposes:['vc_jwt_issuer','oid4vp_request_signing']}, [])
  const payload = createKeyManagementRegistrationPayload(normalizeKeyManagementConfig(original),next,true)
  expect(payload.key_reference_purposes).toEqual({
    previous:{'reserved-key':['lti_tool_signing']},
    'new-service':{'selected-key':['vc_jwt_issuer','oid4vp_request_signing']},
  })
  expect(payload.key_reference_purposes['new-service']).not.toHaveProperty('unselected-alias')
  expect(payload.key_reference_purposes['new-service']['selected-key']).not.toContain('lti_tool_signing')
  expect(payload.type_defaults).toEqual(original.type_defaults)
  expect(payload.format_defaults).toEqual(original.format_defaults)
  expect(payload.default_service_id).toBe('new-service')
  expect(original).toEqual(snapshot)
  expect(() => createKeyManagementRegistrationPayload(payload,next)).toThrow(/fresh identity/)
})

it('registration does not invent purposes or infer a selected key from aliases', () => {
  for (const input of [{key_reference:'selected-key',key_purposes:[]},
    {key_reference:'',key_aliases:'alias-only',key_purposes:['vc_jwt_issuer']}]) {
    const service=createKeyManagementServicePayload({id:'new-service',service_type:'openbao-transit',...input},[])
    expect(createKeyManagementRegistrationPayload({},service).key_reference_purposes).toEqual({})
  }
})

const routingConfig = () => ({
  services: ['first', 'second'].map((id) => ({ id, service_type: 'openbao-transit' })),
  default_service_id: 'first',
  key_reference_purposes: { first: { one: ['vc_jwt_issuer'] }, second: { two: ['oid4vp_request_signing'] } },
  type_defaults: { vc_jwt_issuer: 'first', oid4vp_request_signing: 'second' },
  format_defaults: { JWT: 'first', SD_JWT_VC: 'second' },
})

it('default updates preserve explicit maps and reject unregistered defaults without mutating inputs', () => {
  const original = routingConfig()
  const snapshot = structuredClone(original)
  const payload = createKeyManagementConfigUpdate(original, { default_service_id: 'second' })
  expect(payload.default_service_id).toBe('second')
  for (const field of ['key_reference_purposes', 'type_defaults', 'format_defaults'] as const) {
    expect(payload[field]).toEqual(original[field])
    expect(payload[field]).not.toBe(original[field])
  }
  expect(() => createKeyManagementConfigUpdate(original, { default_service_id: 'foreign' })).toThrow(/registered/)
  expect(original).toEqual(snapshot)
})

it('removal prunes only exact removed-service bindings and handles the last default explicitly', () => {
  const original = routingConfig()
  const snapshot = structuredClone(original)
  const payload = createKeyManagementRemovalPayload(original, 'first')
  expect(payload.services.map((service) => service.id)).toEqual(['second'])
  expect(payload.default_service_id).toBe('second')
  expect(payload.key_reference_purposes).toEqual({ second: { two: ['oid4vp_request_signing'] } })
  expect(payload.type_defaults).toEqual({ oid4vp_request_signing: 'second' })
  expect(payload.format_defaults).toEqual({ SD_JWT_VC: 'second' })
  expect(createKeyManagementRemovalPayload(payload, 'second')).toEqual({
    services: [], default_service_id: null, key_reference_purposes: {}, type_defaults: {}, format_defaults: {},
  })
  expect(createKeyManagementRemovalPayload(original, 'second').default_service_id).toBe('first')
  expect(() => createKeyManagementRemovalPayload(original, 'foreign')).toThrow(/registered/)
  expect(original).toEqual(snapshot)
})
