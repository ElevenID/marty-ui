const DEFAULT_WALLET_OFFER_ERROR = 'Failed to generate wallet offer.';
const MISSING_WALLET_OFFER_ERROR = 'Could not generate a wallet offer. Please try again or contact support.';

export function createWalletOfferDialogState(overrides = {}) {
  return {
    offerData: null,
    loading: false,
    error: null,
    ...overrides,
  };
}

export function resetWalletOfferDialogState() {
  return createWalletOfferDialogState();
}

export function startWalletOfferDialogLoad(currentState = createWalletOfferDialogState()) {
  return {
    ...currentState,
    loading: true,
    error: null,
  };
}

export function resolveWalletOfferDialogLoad(data) {
  if (!data?.offer_url) {
    return createWalletOfferDialogState({
      error: MISSING_WALLET_OFFER_ERROR,
    });
  }

  return createWalletOfferDialogState({
    offerData: data,
  });
}

export function getWalletOfferDialogError(error) {
  return error?.message || DEFAULT_WALLET_OFFER_ERROR;
}

export async function loadWalletOfferDialog({ applicationId, generateIssuanceOffer }) {
  if (!applicationId) {
    return resetWalletOfferDialogState();
  }

  try {
    const data = await generateIssuanceOffer(applicationId);
    return resolveWalletOfferDialogLoad(data);
  } catch (error) {
    return createWalletOfferDialogState({
      error: getWalletOfferDialogError(error),
    });
  }
}

export {
  DEFAULT_WALLET_OFFER_ERROR,
  MISSING_WALLET_OFFER_ERROR,
};
