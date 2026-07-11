import { describe, expect, it, vi } from 'vitest'
import {
  ANY_OID4VCI_WALLET_ID,
  MARTY_AUTHENTICATOR_WALLET_ID,
  DEFAULT_WALLET_OFFER_ERROR,
  MISSING_ISSUANCE_FLOW_ERROR,
  MISSING_WALLET_OFFER_ERROR,
  buildClaimWalletOptions,
  createWalletOfferDialogState,
  getWalletOfferDialogError,
  loadWalletOfferDialog,
  resetWalletOfferDialogState,
  enrichWalletOfferForRouting,
  resolveClaimWalletDeliveryDestinationId,
  resolveClaimWalletSelection,
  resolveWalletOfferDialogLoad,
  resolveWalletOfferRoutingWalletIds,
  selectedClaimWalletIds,
  startWalletOfferDialogLoad,
  walletSupportsBrowserLaunch,
} from './walletOfferDialogUseCases'

describe('walletOfferDialogUseCases', () => {
  it('creates the default dialog state', () => {
    expect(createWalletOfferDialogState()).toEqual({
      offerData: null,
      loading: false,
      error: null,
    })
  })

  it('starts loading while preserving existing offer data', () => {
    expect(startWalletOfferDialogLoad(createWalletOfferDialogState({ offerData: { offer_url: 'openid://offer' } }))).toEqual({
      offerData: { offer_url: 'openid://offer' },
      loading: true,
      error: null,
    })
  })

  it('resolves a successful wallet offer response', () => {
    const data = { offer_url: 'openid://offer', expires_at: '2026-03-16T00:00:00Z' }

    expect(resolveWalletOfferDialogLoad(data)).toEqual({
      offerData: data,
      loading: false,
      error: null,
    })
  })

  it('surfaces a friendly error when the offer url is missing', () => {
    expect(resolveWalletOfferDialogLoad({ status: 'pending' })).toEqual({
      offerData: null,
      loading: false,
      error: MISSING_WALLET_OFFER_ERROR,
    })
  })

  it('normalizes thrown errors', () => {
    expect(getWalletOfferDialogError(new Error('Boom'))).toBe('Boom')
    expect(getWalletOfferDialogError(null)).toBe(DEFAULT_WALLET_OFFER_ERROR)
  })

  it('turns missing issuer flow setup into applicant-friendly guidance', () => {
    expect(getWalletOfferDialogError({
      response: {
        error_description: 'No active issuance flow produced an offer for this application. Configure and activate an OID4VCI flow for the credential template.',
      },
    })).toBe(MISSING_ISSUANCE_FLOW_ERROR)
  })

  it('loads wallet offers through the injected service', async () => {
    const generateIssuanceOffer = vi.fn().mockResolvedValue({ offer_url: 'openid://offer' })

    await expect(loadWalletOfferDialog({ applicationId: 'app-1', generateIssuanceOffer })).resolves.toEqual({
      offerData: { offer_url: 'openid://offer' },
      loading: false,
      error: null,
    })

    expect(generateIssuanceOffer).toHaveBeenCalledWith('app-1')
  })

  it('returns a reset state when no application id is provided', async () => {
    const generateIssuanceOffer = vi.fn()

    await expect(loadWalletOfferDialog({ applicationId: '', generateIssuanceOffer })).resolves.toEqual(
      resetWalletOfferDialogState(),
    )

    expect(generateIssuanceOffer).not.toHaveBeenCalled()
  })

  it('returns an error state when loading fails', async () => {
    const generateIssuanceOffer = vi.fn().mockRejectedValue(new Error('No wallet today'))

    await expect(loadWalletOfferDialog({ applicationId: 'app-1', generateIssuanceOffer })).resolves.toEqual({
      offerData: null,
      loading: false,
      error: 'No wallet today',
    })
  })

  it('falls back to routable registry wallets when no preferred wallet is set', () => {
    const walletIds = resolveWalletOfferRoutingWalletIds({
      offerData: { offer_url: 'https://issuer.example/offers/123' },
      preferredWallets: [],
      registryWallets: [
        {
          id: 'wr-spruce-001',
          name: 'SpruceKit',
          routing_templates: {
            android: 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
          },
        },
        {
          id: 'wr-marty-001',
          name: 'Marty Authenticator',
          routing_templates: { ios: 'marty-authenticator://open?inner={inner_uri_encoded}' },
        },
        {
          id: 'wr-default',
          name: 'Any OID4VCI Wallet',
          deep_link_pattern: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
        },
      ],
    })

    expect(walletIds).toEqual(['wr-spruce-001', 'wr-marty-001'])
  })

  it('ignores protocol-only preferred wallets when choosing same-device routing', () => {
    const walletIds = resolveWalletOfferRoutingWalletIds({
      offerData: { offer_url: 'https://issuer.example/offers/123' },
      preferredWallets: ['wr-lissi-001'],
      registryWallets: [
        {
          id: 'wr-lissi-001',
          name: 'LISSI Wallet',
          deep_link_pattern: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
        },
        {
          id: 'wr-spruce-001',
          name: 'SpruceKit',
          routing_templates: {
            android: 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
          },
        },
      ],
    })

    expect(walletIds).toEqual(['wr-spruce-001'])
  })

  it('ignores protocol-only backend wallet offer keys when choosing same-device routing', () => {
    const walletIds = resolveWalletOfferRoutingWalletIds({
      offerData: {
        offer_url: 'https://issuer.example/offers/123',
        credential_offer_uris: {
          'wr-lissi-001': 'https://issuer.example/offers/lissi',
          'wr-spruce-001': 'https://issuer.example/offers/spruce',
        },
      },
      preferredWallets: [],
      registryWallets: [
        {
          id: 'wr-lissi-001',
          name: 'LISSI Wallet',
          deep_link_pattern: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
        },
        {
          id: 'wr-spruce-001',
          name: 'SpruceKit',
          routing_templates: {
            android: 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
          },
        },
      ],
    })

    expect(walletIds).toEqual(['wr-spruce-001'])
  })

  it('uses known wallet route metadata when registry rows are stale', () => {
    const walletIds = resolveWalletOfferRoutingWalletIds({
      offerData: { offer_url: 'https://issuer.example/offers/123' },
      preferredWallets: ['wr-lissi-001'],
      registryWallets: [
        {
          id: 'wr-lissi-001',
          name: 'LISSI Wallet',
          deep_link_pattern: 'openid-credential-offer://?credential_offer_uri={offer_uri_encoded}',
        },
        {
          id: 'wr-spruce-001',
          name: 'SpruceKit',
        },
      ],
    })

    expect(walletIds).toEqual(['wr-spruce-001'])
  })

  it('enriches an offer with wallet registry routing data', () => {
    const routing = enrichWalletOfferForRouting({
      offerData: { offer_url: 'https://issuer.example/offers/123' },
      registryWallets: [
        {
          id: 'wr-marty-001',
          name: 'Marty Authenticator',
          routing_templates: { ios: 'marty-authenticator://open?inner={inner_uri_encoded}' },
        },
      ],
    })

    expect(routing.walletIds).toEqual(['wr-marty-001'])
    expect(routing.hasWalletRouting).toBe(true)
    expect(routing.offerData).toMatchObject({
      credential_offer_uris: {
        'wr-marty-001': 'https://issuer.example/offers/123',
      },
      credential_offer_labels: {
        'wr-marty-001': 'Marty Authenticator',
      },
      wallet_registry: {
        'wr-marty-001': {
          id: 'wr-marty-001',
        },
      },
    })
  })

  it('builds applicant claim wallet options with browser-compatible wallets first', () => {
    const options = buildClaimWalletOptions({
      registryWallets: [
        {
          id: 'wr-spruce-001',
          name: 'SpruceKit',
          specifications: ['OID4VCI'],
          supported_platforms: ['ios', 'android'],
        },
        {
          id: 'wr-didcomm-001',
          name: 'DIDComm Agent',
          specifications: ['DIDComm v2'],
          supports_qr: false,
          supports_deeplink: false,
        },
        {
          id: 'wr-waltid-001',
          name: 'walt.id Wallet',
          specifications: ['OID4VCI'],
          supported_platforms: ['web', 'ios', 'android'],
        },
      ],
    })

    expect(options.map((wallet) => wallet.id)).toEqual([
      ANY_OID4VCI_WALLET_ID,
      'wr-waltid-001',
      'wr-spruce-001',
    ])
    expect(walletSupportsBrowserLaunch(options[1])).toBe(true)
  })

  it('resolves selected claim wallet ids and delivery channels', () => {
    expect(resolveClaimWalletSelection({
      preferredWallets: ['wr-spruce-001'],
      walletOptions: [
        { id: ANY_OID4VCI_WALLET_ID },
        { id: 'wr-spruce-001' },
      ],
    })).toBe('wr-spruce-001')

    expect(selectedClaimWalletIds(ANY_OID4VCI_WALLET_ID)).toEqual([])
    expect(selectedClaimWalletIds('wr-spruce-001')).toEqual(['wr-spruce-001'])
    expect(resolveClaimWalletDeliveryDestinationId(MARTY_AUTHENTICATOR_WALLET_ID)).toBe('dd-elevenid-wallet')
    expect(resolveClaimWalletDeliveryDestinationId('wr-spruce-001')).toBe('dd-oid4vci-compatible-wallet')
  })
})
