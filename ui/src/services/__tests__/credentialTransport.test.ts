import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  adaptCredentialOfferForWallet,
  buildOid4vciCredentialOfferUri,
  buildOid4vpAuthorizationUri,
  renderWalletRouteTemplate,
} from '../credentialLinkUtils'
import {
  createCredentialOfferTransport,
  createPresentationTransport,
  resolvePreferredCredentialOfferTransport,
  resolvePreferredWalletId,
} from '../walletTransportService'
import {
  DEFAULT_DC_API_PROTOCOL,
  runOpenId4VpDigitalCredentialFlow,
  supportsDigitalCredentials,
} from '../digitalCredentialsApi'

describe('credential link utilities', () => {
  it('wraps by-reference credential offers in a standard OID4VCI deep link', () => {
    expect(buildOid4vciCredentialOfferUri('https://issuer.example/offers/123')).toBe(
      'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
    )
  })

  it('preserves existing standard credential offer and presentation links', () => {
    expect(buildOid4vciCredentialOfferUri('openid-credential-offer://?credential_offer=%7B%7D')).toBe(
      'openid-credential-offer://?credential_offer=%7B%7D',
    )
    expect(buildOid4vpAuthorizationUri('openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Freq')).toBe(
      'openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Freq',
    )
  })

  it('renders wallet-specific outer routing templates without changing the inner URI', () => {
    const innerUri = 'openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Freq%3Fcompat%3Dlissi'
    expect(
      renderWalletRouteTemplate('martywallet://open?inner={inner_uri_encoded}&request={request_uri_encoded}', {
        innerUri,
      }),
    ).toBe(
      'martywallet://open?inner=openid4vp%3A%2F%2Fauthorize%3Frequest_uri%3Dhttps%253A%252F%252Fverifier.example%252Freq%253Fcompat%253Dlissi&request=https%3A%2F%2Fverifier.example%2Freq%3Fcompat%3Dlissi',
    )
  })

  it('preserves inline credential_offer parameters when rendering Spruce routes', () => {
    const offerJson = JSON.stringify({
      credential_issuer: 'https://issuer.example/org/org-1/spruce',
      credential_configuration_ids: ['EmployeeBadge#spruce-sd-jwt'],
      grants: {},
    })
    const innerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`

    expect(
      renderWalletRouteTemplate('openid-credential-offer://?credential_offer_uri={offer_uri_encoded}', {
        innerUri,
      }),
    ).toBe(`openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`)
  })

  it('adapts generic inline offers using the wallet OID4VCI profile', () => {
    const offerJson = JSON.stringify({
      credential_issuer: 'https://beta.elevenidllc.com/org/00000000-0000-0000-0000-000000000001',
      credential_configuration_ids: ['open_badge#sd-jwt'],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': 'code-123',
        },
      },
    })

    const adapted = adaptCredentialOfferForWallet(
      `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`,
      {
        id: 'wr-spruce-001',
        supported_formats: ['spruce-vc+sd-jwt'],
      },
    )

    expect(decodeURIComponent(adapted)).toContain('https://beta.elevenidllc.com/org/00000000-0000-0000-0000-000000000001/spruce')
    expect(decodeURIComponent(adapted)).toContain('open_badge#spruce-sd-jwt')
    expect(decodeURIComponent(adapted)).not.toContain('open_badge#sd-jwt')
  })

  it('does not adapt offers from wallet id alone without profile data', () => {
    const offerJson = JSON.stringify({
      credential_issuer: 'https://beta.elevenidllc.com/org/org-1',
      credential_configuration_ids: ['open_badge#sd-jwt'],
      grants: {},
    })
    const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`

    expect(adaptCredentialOfferForWallet(offerUri, { id: 'wr-spruce-001' })).toBe(offerUri)
  })
})

describe('wallet transport service', () => {
  it('uses wallet routing templates as an outer wrapper for issuance', () => {
    const transport = createCredentialOfferTransport({
      offerUri: 'https://issuer.example/offers/123',
      platform: 'ios',
      wallet: {
        id: 'wr-marty-001',
        ios_deep_link_template: 'martywallet://claim?uri={inner_uri_encoded}',
      },
    })

    expect(transport.innerUri).toBe(
      'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
    )
    expect(transport.openUri).toBe(
      'martywallet://claim?uri=openid-credential-offer%3A%2F%2F%3Fcredential_offer_uri%3Dhttps%253A%252F%252Fissuer.example%252Foffers%252F123',
    )
  })

  it('uses a SpruceID Android intent that preserves the standard OID4VCI payload', () => {
    const transport = createCredentialOfferTransport({
      offerUri: 'https://issuer.example/offers/123',
      platform: 'android',
      wallet: {
        id: 'wr-spruce-001',
        routing_templates: {
          generic: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
          ios: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
          android: 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
        },
      },
    })

    expect(transport.innerUri).toBe(
      'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
    )
    expect(transport.openUri).toBe(
      'intent://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
    )
  })

  it('uses known SpruceID Android intents when registry routing metadata is stale', () => {
    const transport = createCredentialOfferTransport({
      offerUri: 'https://issuer.example/offers/123',
      platform: 'android',
      wallet: {
        id: 'wr-spruce-001',
        name: 'SpruceKit',
        deep_link_pattern: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
      },
    })

    expect(transport.openUri).toBe(
      'intent://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
    )
  })

  it('falls back to the SpruceID nested protocol route on iOS without a universal link', () => {
    const transport = createCredentialOfferTransport({
      offerUri: 'https://issuer.example/offers/123',
      platform: 'ios',
      wallet: {
        id: 'wr-spruce-001',
        name: 'SpruceKit',
        deep_link_pattern: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
      },
    })

    expect(transport.openUri).toBe(
      'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123',
    )
  })

  it('does not mislabel Spruce inline offers as credential_offer_uri values', () => {
    const offerJson = JSON.stringify({
      credential_issuer: 'https://issuer.example/org/org-1/spruce',
      credential_configuration_ids: ['EmployeeBadge#spruce-sd-jwt'],
      grants: {},
    })
    const inlineOffer = `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`
    const transport = createCredentialOfferTransport({
      offerUri: inlineOffer,
      platform: 'android',
      wallet: {
        id: 'wr-spruce-001',
        name: 'SpruceKit',
      },
    })

    expect(transport.innerUri).toBe(inlineOffer)
    expect(transport.openUri).toBe(
      `intent://?credential_offer=${encodeURIComponent(offerJson)}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end`,
    )
    expect(transport.openUri).not.toContain('credential_offer_uri=')
  })

  it('routes selected Spruce wallets through Spruce-specific inline offers when no wallet-specific offer exists', () => {
    const offerJson = JSON.stringify({
      credential_issuer: 'https://beta.elevenidllc.com/org/00000000-0000-0000-0000-000000000001',
      credential_configuration_ids: ['open_badge#sd-jwt'],
      grants: {},
    })

    const resolved = resolvePreferredCredentialOfferTransport({
      preferredWalletIds: ['wr-spruce-001'],
      platform: 'ios',
      offerData: {
        offer_url: `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`,
        wallet_registry: {
          'wr-spruce-001': { id: 'wr-spruce-001', name: 'SpruceKit', supported_formats: ['spruce-vc+sd-jwt'] },
        },
      },
    })

    expect(resolved.walletId).toBe('wr-spruce-001')
    expect(decodeURIComponent(resolved.transport.innerUri)).toContain('/spruce')
    expect(decodeURIComponent(resolved.transport.innerUri)).toContain('open_badge#spruce-sd-jwt')
  })

  it('uses preferred wallet order without wallet-specific hardcoding', () => {
    expect(resolvePreferredWalletId(['wr-default', 'wr-spruce-001'], ['wr-default', 'wr-spruce-001'])).toBe('wr-default')
  })

  it('does not prefer an unselected Spruce SDK wallet over the selected wallet', () => {
    expect(resolvePreferredWalletId(['wr-lissi-001', 'wr-spruce-001'], ['wr-lissi-001'])).toBe('wr-lissi-001')
  })

  it('prefers the selected wallet-specific offer over the generic default for mobile handoff', () => {
    const resolved = resolvePreferredCredentialOfferTransport({
      preferredWalletIds: ['wr-spruce-001'],
      platform: 'ios',
      offerData: {
        offer_url: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fgeneric',
        credential_offer_uris: {
          'wr-spruce-001': 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Forg%2Forg-1%2Fspruce%2Foffers%2F123',
        },
      },
    })

    expect(resolved.walletId).toBe('wr-spruce-001')
    expect(decodeURIComponent(resolved.offerUri)).toContain('/spruce/offers/123')
    expect(decodeURIComponent(resolved.transport.innerUri)).toContain('/spruce/offers/123')
  })

  it('does not let a generic default transport artifact override a selected wallet-specific offer', () => {
    const resolved = resolvePreferredCredentialOfferTransport({
      preferredWalletIds: ['wr-spruce-001'],
      platform: 'ios',
      offerData: {
        offer_url: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fgeneric',
        credential_offer_uris: {
          'wr-spruce-001': 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Forg%2Forg-1%2Fspruce%2Foffers%2F123',
        },
        transport_artifacts: {
          default: {
            innerUri: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fgeneric',
            openUri: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fgeneric',
          },
        },
      },
    })

    expect(decodeURIComponent(resolved.transport.innerUri)).toContain('/spruce/offers/123')
  })

  it('falls back to a standard OID4VP link when no wallet route exists', () => {
    const transport = createPresentationTransport({
      requestUri: 'https://verifier.example/v1/flows/instances/abc/request',
      platform: 'android',
    })

    expect(transport.openUri).toBe(
      'openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Fv1%2Fflows%2Finstances%2Fabc%2Frequest',
    )
  })
})

describe('digital credentials api adapter', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
    Object.defineProperty(globalThis, 'DigitalCredential', {
      configurable: true,
      value: { userAgentAllowsProtocol: vi.fn(() => true) },
    })
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: {
        get: vi.fn().mockResolvedValue({
          protocol: DEFAULT_DC_API_PROTOCOL,
          data: { vp_token: 'vp-token' },
        }),
      },
    })
  })

  it('checks secure-context protocol support', async () => {
    await expect(supportsDigitalCredentials()).resolves.toBe(true)
  })

  it('fetches the request jwt, launches the wallet chooser, and submits the response', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, text: () => Promise.resolve('signed-request-jwt') })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ status: 'completed' }) })

    await expect(
      runOpenId4VpDigitalCredentialFlow({
        requestUrl: '/v1/flows/instances/abc/request?transport=dc_api',
        submitUrl: '/v1/flows/instances/abc/submit/dc-api',
        fetchImpl,
      }),
    ).resolves.toEqual({ status: 'completed' })

    expect(navigator.credentials.get).toHaveBeenCalledWith({
      mediation: 'required',
      digital: {
        requests: [
          {
            protocol: DEFAULT_DC_API_PROTOCOL,
            data: { request: 'signed-request-jwt' },
          },
        ],
      },
    })
    expect(fetchImpl).toHaveBeenLastCalledWith(
      expect.stringMatching(/\/v1\/flows\/instances\/abc\/submit\/dc-api$/),
      expect.objectContaining({ method: 'POST' }),
    )
  })
})
