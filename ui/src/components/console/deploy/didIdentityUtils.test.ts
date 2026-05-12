import { describe, expect, it } from 'vitest'
import { buildDidIdentities, buildDidMethodCatalog } from './didIdentityUtils'

const EC_JWK = { kty: 'EC', crv: 'P-256', x: 'abc123', y: 'def456', kid: 'key-1' }

const KEY_WITH_JWK = {
  id: 'k1',
  provider_key_name: 'cred-issuer-test-es256',
  name: 'Test issuer key',
  status: 'active',
  public_jwk: EC_JWK,
}

const KEY_WITH_MULTIBASE = {
  id: 'k2',
  provider_key_name: 'cred-issuer-test-eddsa',
  name: 'Test EdDSA key',
  status: 'active',
  public_key_multibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
}

const KEY_WITH_VALID_P256_JWK = {
  id: 'k4',
  provider_key_name: 'cred-issuer-test-valid-p256',
  name: 'Test valid P-256 key',
  status: 'active',
  public_jwk: {
    kty: 'EC',
    crv: 'P-256',
    x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    kid: 'k4',
  },
}

const KEY_WITHOUT_PUBLIC_MATERIAL = {
  id: 'k3',
  provider_key_name: 'cred-issuer-test-no-pubkey',
  name: 'Key without public material',
  status: 'active',
}

const DOMAIN_SUMMARY = {
  public_domain: 'beta.example.com',
  issuer_base_url: 'https://beta.example.com',
}

describe('buildDidIdentities', () => {
  it('derives a did:jwk from a key with public_jwk', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_JWK], domainSummary: null })
    const jwkId = identities.find((id) => id.method === 'did:jwk')

    expect(jwkId).toBeDefined()
    expect(jwkId?.did).toMatch(/^did:jwk:/)
    expect(jwkId?.status).toBe('ready')
    expect(jwkId?.backingKeyId).toBe('k1')
  })

  it('derives a did:key from a key with public_key_multibase', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_MULTIBASE], domainSummary: null })
    const keyId = identities.find((id) => id.method === 'did:key')

    expect(keyId).toBeDefined()
    expect(keyId?.did).toMatch(/^did:key:z/)
    expect(keyId?.status).toBe('ready')
  })

  it('derives a did:key from a valid P-256 public JWK', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_VALID_P256_JWK], domainSummary: null })
    const keyId = identities.find((id) => id.method === 'did:key')

    expect(keyId).toBeDefined()
    expect(keyId?.did).toMatch(/^did:key:z/)
    expect(keyId?.status).toBe('ready')
  })

  it('derives a did:web when a domain summary is present', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_JWK], domainSummary: DOMAIN_SUMMARY })
    const webId = identities.find((id) => id.method === 'did:web')

    expect(webId).toBeDefined()
    expect(webId?.did).toBe('did:web:beta.example.com')
    expect(webId?.status).toBe('ready')
    expect(webId?.documentKind).toBe('document')
  })

  it('produces a did:web template when no key exposes a public JWK', () => {
    const identities = buildDidIdentities({
      keys: [KEY_WITHOUT_PUBLIC_MATERIAL],
      domainSummary: DOMAIN_SUMMARY,
    })
    const webId = identities.find((id) => id.method === 'did:web')

    expect(webId).toBeDefined()
    expect(webId?.status).toBe('draft')
    expect(webId?.documentKind).toBe('template')
  })

  it('does not derive did:jwk from a key without public_jwk', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITHOUT_PUBLIC_MATERIAL], domainSummary: null })
    expect(identities.find((id) => id.method === 'did:jwk')).toBeUndefined()
  })

  it('does not derive did:key from a key without multibase material', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_JWK], domainSummary: null })
    expect(identities.find((id) => id.method === 'did:key')).toBeUndefined()
  })

  it('returns empty array when keys is empty and no domain is provided', () => {
    const identities = buildDidIdentities({ keys: [], domainSummary: null })
    expect(identities).toEqual([])
  })

  it('does not produce duplicate DIDs when duplicate keys are passed', () => {
    const identities = buildDidIdentities({
      keys: [KEY_WITH_JWK, KEY_WITH_JWK],
      domainSummary: DOMAIN_SUMMARY,
    })
    const dids = identities.map((id) => id.did)
    expect(new Set(dids).size).toBe(dids.length)
  })

  it('embeds canonical (key-sorted) JWK in the did:jwk identifier', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_JWK], domainSummary: null })
    const jwkId = identities.find((id) => id.method === 'did:jwk')!
    const base64Part = jwkId.did.replace('did:jwk:', '')

    // Pad base64url back to standard base64 before decoding
    const padded = base64Part.replace(/-/g, '+').replace(/_/g, '/')
    const decoded = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'))

    const keys = Object.keys(decoded)
    expect(keys).toEqual([...keys].sort())
  })

  it('includes a verificationMethod in the did:jwk document', () => {
    const identities = buildDidIdentities({ keys: [KEY_WITH_JWK], domainSummary: null })
    const jwkId = identities.find((id) => id.method === 'did:jwk')!

    expect(jwkId.document.verificationMethod).toHaveLength(1)
    expect(jwkId.document.verificationMethod[0].publicKeyJwk).toBeDefined()
    expect(jwkId.document.verificationMethod[0].publicKeyJwk.kty).toBe('EC')
  })

  it('builds both did:jwk and did:key when a key has both public_jwk and multibase', () => {
    const hybridKey = { ...KEY_WITH_JWK, public_key_multibase: KEY_WITH_MULTIBASE.public_key_multibase }
    const identities = buildDidIdentities({ keys: [hybridKey], domainSummary: null })

    expect(identities.find((id) => id.method === 'did:jwk')).toBeDefined()
    expect(identities.find((id) => id.method === 'did:key')).toBeDefined()
  })
})

describe('buildDidMethodCatalog', () => {
  it('marks did:jwk as Ready now when a key has a public JWK', () => {
    const catalog = buildDidMethodCatalog([KEY_WITH_JWK], null)
    const entry = catalog.find((e) => e.method === 'did:jwk')!

    expect(entry.ready).toBe(true)
    expect(entry.readinessLabel).toBe('Ready now')
    expect(entry.blockers).toHaveLength(0)
  })

  it('marks did:jwk as Setup required when no key has a public JWK', () => {
    const catalog = buildDidMethodCatalog([KEY_WITHOUT_PUBLIC_MATERIAL], null)
    const entry = catalog.find((e) => e.method === 'did:jwk')!

    expect(entry.ready).toBe(false)
    expect(entry.readinessLabel).toBe('Setup required')
    expect(entry.blockers.length).toBeGreaterThan(0)
  })

  it('marks did:key as Ready now when a key has multibase material', () => {
    const catalog = buildDidMethodCatalog([KEY_WITH_MULTIBASE], null)
    const entry = catalog.find((e) => e.method === 'did:key')!

    expect(entry.ready).toBe(true)
    expect(entry.readinessLabel).toBe('Ready now')
  })

  it('marks did:key as Setup required when no key has multibase material', () => {
    const catalog = buildDidMethodCatalog([KEY_WITH_JWK], null)
    const entry = catalog.find((e) => e.method === 'did:key')!

    expect(entry.ready).toBe(false)
    expect(entry.readinessLabel).toBe('Setup required')
  })

  it('marks did:web as Ready now when domain and public JWK are both present', () => {
    const catalog = buildDidMethodCatalog([KEY_WITH_JWK], DOMAIN_SUMMARY)
    const entry = catalog.find((e) => e.method === 'did:web')!

    expect(entry.ready).toBe(true)
    expect(entry.readinessLabel).toBe('Ready now')
  })

  it('marks did:web as Template available when domain is set but no key has a public JWK', () => {
    const catalog = buildDidMethodCatalog([KEY_WITHOUT_PUBLIC_MATERIAL], DOMAIN_SUMMARY)
    const entry = catalog.find((e) => e.method === 'did:web')!

    expect(entry.ready).toBe(true)
    expect(entry.readinessLabel).toBe('Template available')
    expect(entry.blockers.length).toBeGreaterThan(0)
  })

  it('marks did:web as Setup required when no domain is configured', () => {
    const catalog = buildDidMethodCatalog([KEY_WITH_JWK], null)
    const entry = catalog.find((e) => e.method === 'did:web')!

    expect(entry.ready).toBe(false)
    expect(entry.readinessLabel).toBe('Setup required')
    expect(entry.blockers.length).toBeGreaterThan(0)
  })

  it('returns an entry for each of the three supported DID methods', () => {
    const catalog = buildDidMethodCatalog([], null)
    const methods = catalog.map((e) => e.method)

    expect(methods).toContain('did:web')
    expect(methods).toContain('did:jwk')
    expect(methods).toContain('did:key')
    expect(catalog).toHaveLength(3)
  })

  it('handles an empty key list without throwing', () => {
    expect(() => buildDidMethodCatalog([], null)).not.toThrow()
    expect(() => buildDidMethodCatalog([], DOMAIN_SUMMARY)).not.toThrow()
  })
})
