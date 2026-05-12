const DEFAULT_WALLET_OFFER_ERROR = 'Failed to generate wallet offer.';
const MISSING_WALLET_OFFER_ERROR = 'Could not generate a wallet offer. Please try again or contact support.';
const FALLBACK_WALLET_PRIORITY = ['wr-spruce-001', 'wr-marty-001', 'spruce', 'sprucekit', 'marty'];
const PROTOCOL_ROUTE_SCHEMES = new Set(['openid-credential-offer', 'openid4vp', 'haip-vci', 'haip-vp']);
const ROUTE_PLACEHOLDER = /\{(?:inner_uri|uri|offer_uri|offer|credential_offer_uri|request_uri)(?:_encoded)?\}/;
const KNOWN_WALLET_ROUTE_TEMPLATES = {
  'wr-spruce-001': ['openid-credential-offer://?credential_offer_uri={offer_uri_encoded}', 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end'],
  spruce: ['openid-credential-offer://?credential_offer_uri={offer_uri_encoded}', 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end'],
  sprucekit: ['openid-credential-offer://?credential_offer_uri={offer_uri_encoded}', 'intent://?credential_offer_uri={offer_uri_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end'],
  'wr-marty-001': ['marty-authenticator://open?inner={inner_uri_encoded}'],
  marty: ['marty-authenticator://open?inner={inner_uri_encoded}'],
};

function uniqueWalletIds(walletIds = []) {
  return [...new Set(walletIds.filter(Boolean))];
}

function getBaseOfferUri(offerData) {
  return offerData?.offer_url || offerData?.credential_offer_uri || null;
}

function getWalletRouteTemplates(wallet = {}) {
  return [
    wallet.deep_link_pattern,
    wallet.deep_link_template,
    ...Object.values(wallet.routing_templates || {}),
    ...(KNOWN_WALLET_ROUTE_TEMPLATES[wallet.id] || KNOWN_WALLET_ROUTE_TEMPLATES[wallet.wallet_id] || []),
  ].filter(Boolean);
}

function getTemplateScheme(template) {
  return String(template || '').trim().match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase() || '';
}

function isWalletRouteTemplate(template) {
  const source = String(template || '');
  const scheme = getTemplateScheme(source);
  return Boolean(
    source &&
    ROUTE_PLACEHOLDER.test(source) &&
    !PROTOCOL_ROUTE_SCHEMES.has(scheme)
  );
}

function hasNestedWalletRoute(wallet) {
  if (!wallet || wallet.supports_deeplink === false) return false;
  return getWalletRouteTemplates(wallet).some(isWalletRouteTemplate);
}

function buildWalletLookup({ offerData, registryWallets = [] } = {}) {
  const walletLookup = new Map();

  for (const registryWallet of registryWallets) {
    if (registryWallet?.id) walletLookup.set(registryWallet.id, registryWallet);
  }

  for (const wallet of Object.values(offerData?.wallet_registry || {})) {
    if (wallet?.id) walletLookup.set(wallet.id, wallet);
  }

  for (const wallet of Object.values(offerData?.wallets_by_id || {})) {
    if (wallet?.id) walletLookup.set(wallet.id, wallet);
  }

  return walletLookup;
}

function filterRoutableWalletIds(walletIds, walletLookup) {
  return uniqueWalletIds(walletIds).filter((walletId) => hasNestedWalletRoute(walletLookup.get(walletId)));
}

function sortFallbackWallets(registryWallets = []) {
  const priority = new Map(FALLBACK_WALLET_PRIORITY.map((walletId, index) => [walletId, index]));
  return [...registryWallets]
    .filter(hasNestedWalletRoute)
    .sort((leftWallet, rightWallet) => {
      const leftPriority = priority.get(leftWallet.id) ?? Number.MAX_SAFE_INTEGER;
      const rightPriority = priority.get(rightWallet.id) ?? Number.MAX_SAFE_INTEGER;
      if (leftPriority !== rightPriority) return leftPriority - rightPriority;
      return String(leftWallet.name || leftWallet.id).localeCompare(String(rightWallet.name || rightWallet.id));
    });
}

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

export function buildWalletRegistryMaps(registryWallets = []) {
  const walletMap = {};
  const labelMap = {};

  for (const registryWallet of registryWallets) {
    if (!registryWallet?.id) continue;
    walletMap[registryWallet.id] = registryWallet;
    labelMap[registryWallet.id] = registryWallet.name || registryWallet.id;
  }

  return { walletMap, labelMap };
}

export function resolveWalletOfferRoutingWalletIds({
  offerData,
  preferredWallets = [],
  registryWallets = [],
} = {}) {
  const walletLookup = buildWalletLookup({ offerData, registryWallets });
  const preferredIds = filterRoutableWalletIds(preferredWallets, walletLookup);
  if (preferredIds.length > 0) return preferredIds;

  const backendWalletIds = filterRoutableWalletIds(Object.keys(offerData?.credential_offer_uris || {}), walletLookup)
    .filter((walletId) => walletId !== 'wr-default');
  if (backendWalletIds.length > 0) return backendWalletIds;

  if (!getBaseOfferUri(offerData)) return [];
  return uniqueWalletIds(sortFallbackWallets(registryWallets).map((registryWallet) => registryWallet.id));
}

export function enrichWalletOfferForRouting({
  offerData,
  preferredWallets = [],
  registryWallets = [],
} = {}) {
  if (!offerData) {
    return {
      offerData,
      walletIds: [],
      hasWalletRouting: false,
    };
  }

  const walletIds = resolveWalletOfferRoutingWalletIds({
    offerData,
    preferredWallets,
    registryWallets,
  });
  const { walletMap, labelMap } = buildWalletRegistryMaps(registryWallets);
  const baseOfferUri = getBaseOfferUri(offerData);
  const credentialOfferUris = { ...(offerData.credential_offer_uris || {}) };
  const credentialOfferLabels = { ...(offerData.credential_offer_labels || {}) };

  for (const walletId of walletIds) {
    if (baseOfferUri && !credentialOfferUris[walletId]) {
      credentialOfferUris[walletId] = baseOfferUri;
    }
    if (!credentialOfferLabels[walletId]) {
      credentialOfferLabels[walletId] = labelMap[walletId] || walletId;
    }
  }

  return {
    offerData: {
      ...offerData,
      credential_offer_uris: credentialOfferUris,
      credential_offer_labels: credentialOfferLabels,
      wallet_registry: {
        ...(offerData.wallet_registry || {}),
        ...walletMap,
      },
      wallets_by_id: {
        ...(offerData.wallets_by_id || {}),
        ...walletMap,
      },
    },
    walletIds,
    hasWalletRouting: walletIds.length > 0,
  };
}

export function getWalletOfferPrimaryUri(offerData, walletId) {
  if (!offerData) return null;
  return (walletId ? offerData.credential_offer_uris?.[walletId] : null) || getBaseOfferUri(offerData);
}

export {
  DEFAULT_WALLET_OFFER_ERROR,
  MISSING_WALLET_OFFER_ERROR,
};
