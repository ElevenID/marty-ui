const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/jws-2020/v1',
]

const METHOD_DEFINITIONS = [
  {
    method: 'did:web',
    label: 'did:web',
    resolverMode: 'Hosted document',
    requirements: ['Public domain or issuer base URL', 'Public verification key material'],
    description: 'Best fit for production issuers with a managed or self-hosted web domain.',
  },
  {
    method: 'did:jwk',
    label: 'did:jwk',
    resolverMode: 'Self-contained identifier',
    requirements: ['Public JWK'],
    description: 'Portable DID derived directly from a public JWK. No hosting required.',
  },
  {
    method: 'did:key',
    label: 'did:key',
    resolverMode: 'Self-derived from multibase key',
    requirements: ['Public multibase key'],
    description: 'Compact DID derived from public multibase key material, useful for local and agent identities.',
  },
]

export const getDidIdentityTabs = () => [
  { label: 'Identities', path: '/console/org/deploy/issuer-identity' },
]

export const getKeyManagementTabs = () => [
  { label: 'Keys', path: '/console/org/deploy/key-management' },
  { label: 'Services', path: '/console/org/deploy/key-management/services' },
]

export const getDidIdentityBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: 'Issuer Identity', path: '/console/org/deploy/issuer-identity' },
]

const normalizeString = (value) => (typeof value === 'string' ? value.trim() : '')

const normalizeLower = (value) => normalizeString(value).toLowerCase()

const parseJsonIfNeeded = (value) => {
  if (!value) {
    return null
  }
  if (typeof value === 'object') {
    return value
  }
  if (typeof value !== 'string') {
    return null
  }

  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

const sortObject = (value) => {
  if (Array.isArray(value)) {
    return value.map(sortObject)
  }
  if (!value || typeof value !== 'object') {
    return value
  }

  return Object.keys(value)
    .sort()
    .reduce((result, key) => {
      result[key] = sortObject(value[key])
      return result
    }, {})
}

const toBase64Url = (input) => {
  // eslint-disable-next-line no-undef
  if (typeof Buffer !== 'undefined') {
    // eslint-disable-next-line no-undef
    return Buffer.from(input, 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  const encoder = new TextEncoder()
  const bytes = encoder.encode(input)
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })

  return window.btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

const base64UrlToBytes = (value) => {
  if (typeof value !== 'string' || !value.trim()) {
    return null
  }

  const normalized = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=')

  try {
    // eslint-disable-next-line no-undef
    if (typeof Buffer !== 'undefined') {
      // eslint-disable-next-line no-undef
      return Uint8Array.from(Buffer.from(normalized, 'base64'))
    }

    const binary = window.atob(normalized)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes
  } catch {
    return null
  }
}

const bytesToBase58 = (bytes) => {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    return ''
  }

  let value = 0n
  bytes.forEach((byte) => {
    value = (value << 8n) + BigInt(byte)
  })

  let encoded = ''
  while (value > 0n) {
    const mod = Number(value % 58n)
    encoded = BASE58_ALPHABET[mod] + encoded
    value /= 58n
  }

  let leadingZeros = 0
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    encoded = BASE58_ALPHABET[0] + encoded
    leadingZeros += 1
  }

  return encoded || BASE58_ALPHABET[0]
}

const concatBytes = (...chunks) => {
  const totalLength = chunks.reduce((sum, part) => sum + (part?.length || 0), 0)
  const merged = new Uint8Array(totalLength)
  let offset = 0

  chunks.forEach((part) => {
    if (!(part instanceof Uint8Array)) {
      return
    }
    merged.set(part, offset)
    offset += part.length
  })

  return merged
}

const getPublicJwk = (key) => {
  const candidate = parseJsonIfNeeded(
    key?.public_jwk
    || key?.publicKeyJwk
    || key?.jwk
    || key?.publicKey
  )

  if (candidate && typeof candidate === 'object') {
    const sanitized = { ...candidate }
    delete sanitized.d
    return Object.keys(sanitized).length > 0 ? sanitized : null
  }

  const jwk = {
    kty: normalizeString(key?.kty),
    crv: normalizeString(key?.crv),
    x: normalizeString(key?.x),
    y: normalizeString(key?.y),
    n: normalizeString(key?.n),
    e: normalizeString(key?.e),
    kid: normalizeString(key?.kid || key?.provider_key_name || key?.id),
  }

  if (!jwk.kty) {
    return null
  }

  const compact = Object.fromEntries(Object.entries(jwk).filter(([, value]) => value))
  return Object.keys(compact).length > 0 ? compact : null
}

const deriveMultibaseFromPublicJwk = (jwk) => {
  if (!jwk || typeof jwk !== 'object') {
    return ''
  }

  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
    const xBytes = base64UrlToBytes(jwk.x)
    if (!xBytes || xBytes.length !== 32) {
      return ''
    }
    const prefixed = concatBytes(Uint8Array.from([0xED, 0x01]), xBytes)
    return `z${bytesToBase58(prefixed)}`
  }

  if (jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
    const xBytes = base64UrlToBytes(jwk.x)
    const yBytes = base64UrlToBytes(jwk.y)
    if (!xBytes || !yBytes || xBytes.length !== 32 || yBytes.length !== 32) {
      return ''
    }

    const prefix = (yBytes[31] & 1) === 1 ? 0x03 : 0x02
    const compressedPoint = concatBytes(Uint8Array.from([prefix]), xBytes)
    const multicodec = concatBytes(Uint8Array.from([0x80, 0x24]), compressedPoint)
    return `z${bytesToBase58(multicodec)}`
  }

  return ''
}

const getPublicMultibase = (key) => {
  const explicit = normalizeString(key?.public_key_multibase || key?.publicKeyMultibase || key?.multibase)
  if (explicit) {
    return explicit
  }

  return deriveMultibaseFromPublicJwk(getPublicJwk(key))
}

const getHostFromDomainSummary = (domainSummary) => {
  const issuerBaseUrl = normalizeString(domainSummary?.issuer_base_url)
  if (issuerBaseUrl) {
    try {
      const parsed = new URL(issuerBaseUrl)
      const host = parsed.hostname
      const pathSegments = parsed.pathname.split('/').filter(Boolean)
      return pathSegments.length > 0 ? `${host}:${pathSegments.join(':')}` : host
    } catch {
      return issuerBaseUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
    }
  }

  return normalizeString(domainSummary?.public_domain)
}

const getAssociationLabel = (key) => {
  const hints = [
    key?.provider_key_name,
    key?.name,
    key?.id,
    ...(Array.isArray(key?.aliases) ? key.aliases : []),
    ...(Array.isArray(key?.key_aliases) ? key.key_aliases : []),
  ]
    .map(normalizeLower)
    .filter(Boolean)
    .join(' ')

  if (/cred-dsc|document signer|doc signer|\bdsc\b/.test(hints)) {
    return 'Document signer certificate'
  }

  if (/csca|iaca|root certificate|root cert|issuing authority/.test(hints)) {
    return 'Issuing authority certificate'
  }

  if (/cred-issuer|issuer key|vc issuer|credential issuer/.test(hints)) {
    return 'Credential issuer signing'
  }

  return 'Managed signing key'
}

const getVerificationMethodSuffix = (key) => normalizeString(
  key?.provider_key_name || key?.kid || key?.id || 'key-1'
)
  .replace(/[^a-zA-Z0-9._-]/g, '-')

const buildVerificationMethod = (did, key, publicJwk, fallbackType = 'JsonWebKey2020') => ({
  id: `${did}#${getVerificationMethodSuffix(key)}`,
  type: fallbackType,
  controller: did,
  ...(publicJwk ? { publicKeyJwk: publicJwk } : {}),
  ...(getPublicMultibase(key) ? { publicKeyMultibase: getPublicMultibase(key) } : {}),
})

const buildDidJwkIdentity = (key) => {
  const publicJwk = getPublicJwk(key)
  if (!publicJwk) {
    return null
  }

  const canonicalJwk = sortObject(publicJwk)
  const did = `did:jwk:${toBase64Url(JSON.stringify(canonicalJwk))}`
  const verificationMethod = buildVerificationMethod(did, key, canonicalJwk)

  return {
    id: `did-jwk-${key.id}`,
    method: 'did:jwk',
    label: key.name || key.provider_key_name || key.id,
    did,
    source: key.provider_key_name || key.id,
    associatedWith: getAssociationLabel(key),
    status: 'ready',
    readinessLabel: 'Ready',
    issues: [],
    backingKeyId: key.id,
    documentKind: 'document',
    document: {
      '@context': DID_CONTEXT,
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethod.id],
      assertionMethod: [verificationMethod.id],
    },
  }
}

const buildDidKeyIdentity = (key) => {
  const multibase = getPublicMultibase(key)
  if (!multibase) {
    return null
  }

  const normalized = multibase.startsWith('z') ? multibase : `z${multibase}`
  const did = `did:key:${normalized}`
  const verificationMethod = buildVerificationMethod(did, key, null, 'Multikey')

  return {
    id: `did-key-${key.id}`,
    method: 'did:key',
    label: key.name || key.provider_key_name || key.id,
    did,
    source: key.provider_key_name || key.id,
    associatedWith: getAssociationLabel(key),
    status: 'ready',
    readinessLabel: 'Ready',
    issues: [],
    backingKeyId: key.id,
    documentKind: 'document',
    document: {
      '@context': DID_CONTEXT,
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethod.id],
      assertionMethod: [verificationMethod.id],
    },
  }
}

const buildDidWebIdentity = (key, domainSummary) => {
  const host = getHostFromDomainSummary(domainSummary)
  if (!host) {
    return null
  }

  const did = `did:web:${host.replace(/\//g, ':')}`
  const publicJwk = getPublicJwk(key)
  const verificationMethod = buildVerificationMethod(did, key, publicJwk)
  const issues = []

  if (!publicJwk) {
    issues.push('Public JWK is not exposed by the current signing service, so the DID document is a publishable template rather than a final DID document.')
  }

  return {
    id: `did-web-${key?.id || host}`,
    method: 'did:web',
    label: host,
    did,
    source: host,
    associatedWith: key ? getAssociationLabel(key) : 'Domain-managed issuer identity',
    status: publicJwk ? 'ready' : 'draft',
    readinessLabel: publicJwk ? 'Ready' : 'Draft',
    issues,
    backingKeyId: key?.id || null,
    documentKind: publicJwk ? 'document' : 'template',
    document: {
      '@context': DID_CONTEXT,
      id: did,
      verificationMethod: [
        publicJwk
          ? verificationMethod
          : {
              id: verificationMethod.id,
              type: verificationMethod.type,
              controller: did,
              publicKeyJwk: {
                note: 'Replace with the public JWK for the bound signing key before publishing did.json.',
              },
            },
      ],
      authentication: [verificationMethod.id],
      assertionMethod: [verificationMethod.id],
      service: [
        {
          id: `${did}#issuer`,
          type: 'LinkedDomains',
          serviceEndpoint: normalizeString(domainSummary?.issuer_base_url) || `https://${host.replace(/:/g, '/')}`,
        },
      ],
    },
  };
}

export const buildDidMethodCatalog = (keys, domainSummary) => {
  const safeKeys = Array.isArray(keys) ? keys : []

  return METHOD_DEFINITIONS.map((definition) => {
    let ready = false
    let readinessLabel = 'Setup required'
    let readinessColor = 'warning'
    let blockers = []

    if (definition.method === 'did:web') {
      const hasHost = Boolean(getHostFromDomainSummary(domainSummary))
      const hasPublicJwk = safeKeys.some((key) => getPublicJwk(key))

      if (!hasHost) {
        blockers = ['Set a public domain or issuer base URL to prepare did:web identities.']
      } else if (!hasPublicJwk) {
        ready = true
        readinessLabel = 'Template available'
        blockers = ['No signing key exposes a public JWK yet, so only a did.json template can be generated.']
      } else {
        ready = true
        readinessLabel = 'Ready now'
        readinessColor = 'success'
      }
    }

    if (definition.method === 'did:jwk') {
      ready = safeKeys.some((key) => getPublicJwk(key))
      if (!ready) {
        blockers = ['No signing key exposes a public JWK yet, so did:jwk cannot be derived.']
      } else {
        readinessLabel = 'Ready now'
        readinessColor = 'success'
      }
    }

    if (definition.method === 'did:key') {
      ready = safeKeys.some((key) => getPublicMultibase(key))
      if (!ready) {
        blockers = ['No signing key exposes public multibase material yet, so did:key cannot be derived.']
      } else {
        readinessLabel = 'Ready now'
        readinessColor = 'success'
      }
    }

    return {
      ...definition,
      ready,
      readinessLabel,
      readinessColor,
      blockers,
    }
  })
}

export const buildDidIdentities = ({ keys, domainSummary }) => {
  const safeKeys = Array.isArray(keys) ? keys : []
  const candidates = []
  const seen = new Set()
  const activeKeys = safeKeys.filter((key) => normalizeLower(key.status) === 'active')
  const primaryKey = activeKeys[0] || safeKeys[0] || null

  if (primaryKey) {
    const didWeb = buildDidWebIdentity(primaryKey, domainSummary)
    if (didWeb && !seen.has(didWeb.did)) {
      candidates.push(didWeb)
      seen.add(didWeb.did)
    }
  } else {
    const didWeb = buildDidWebIdentity(null, domainSummary)
    if (didWeb && !seen.has(didWeb.did)) {
      candidates.push(didWeb)
      seen.add(didWeb.did)
    }
  }

  safeKeys.forEach((key) => {
    const didJwk = buildDidJwkIdentity(key)
    if (didJwk && !seen.has(didJwk.did)) {
      candidates.push(didJwk)
      seen.add(didJwk.did)
    }

    const didKey = buildDidKeyIdentity(key)
    if (didKey && !seen.has(didKey.did)) {
      candidates.push(didKey)
      seen.add(didKey.did)
    }
  })

  return candidates
}