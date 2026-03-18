import { describe, expect, it, vi } from 'vitest'
import {
  DEFAULT_WALLET_OFFER_ERROR,
  MISSING_WALLET_OFFER_ERROR,
  createWalletOfferDialogState,
  getWalletOfferDialogError,
  loadWalletOfferDialog,
  resetWalletOfferDialogState,
  resolveWalletOfferDialogLoad,
  startWalletOfferDialogLoad,
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
})
