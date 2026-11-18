import { getPlatform } from '../utils/deviceDetection';
import {
  adaptCredentialOfferForWallet,
  buildOid4vciCredentialOfferUri,
  buildOid4vpAuthorizationUri,
  resolveWalletOpenUri,
} from './credentialLinkUtils';

export const TRANSPORT_METHODS = {
  DIGITAL_CREDENTIALS: 'digital_credentials',
  WALLET_LINK: 'wallet_link',
  STANDARD_LINK: 'standard_link',
  QR: 'qr',
  COPY: 'copy',
};

/**
 * @param {{ offerUri?: string, wallet?: Record<string, any> | null, platform?: string, walletId?: string }} [options]
 */
export function createCredentialOfferTransport({ offerUri, wallet = null, platform = getPlatform(), walletId = '' } = {}) {
  const resolvedWalletId = walletId || wallet?.id || '';
  const walletAwareOfferUri = adaptCredentialOfferForWallet(offerUri, wallet);
  const standardUri = buildOid4vciCredentialOfferUri(walletAwareOfferUri);
  const walletUri = resolveWalletOpenUri({ wallet, innerUri: standardUri, platform, walletId });
  return {
    kind: 'oid4vci',
    platform,
    walletId: resolvedWalletId,
    innerUri: standardUri,
    qrUri: standardUri,
    copyUri: standardUri,
    openUri: walletUri || standardUri,
    method: walletUri ? TRANSPORT_METHODS.WALLET_LINK : TRANSPORT_METHODS.STANDARD_LINK,
  };
}

/**
 * @param {string[]} [walletIds]
 * @param {string[]} [preferredWalletIds]
 */
export function resolvePreferredWalletId(walletIds = [], preferredWalletIds = []) {
  const availableIds = Array.from(new Set((Array.isArray(walletIds) ? walletIds : []).filter(Boolean)));
  if (availableIds.length === 0) return '';

  const preferredIds = Array.isArray(preferredWalletIds) ? preferredWalletIds.filter(Boolean) : [];
  const preferredMatches = preferredIds.filter((id) => availableIds.includes(id));
  const orderedIds = preferredMatches.length > 0 ? preferredMatches : availableIds;

  return orderedIds[0] || '';
}

export function resolveWalletTransportArtifact(artifacts, walletId) {
  if (!artifacts) return null;
  if (!walletId) return resolveTransportArtifact(artifacts, null);
  return artifacts.wallets?.[walletId] || artifacts[walletId] || null;
}

/**
 * @param {{ offerData?: Record<string, any> | null, preferredWalletIds?: string[], platform?: string }} [options]
 */
export function resolvePreferredCredentialOfferTransport({ offerData = null, preferredWalletIds = [], platform = getPlatform() } = {}) {
  const walletOfferUris = offerData?.credential_offer_uris || {};
  const walletOfferIds = Object.keys(walletOfferUris);
  const walletId = resolvePreferredWalletId(walletOfferIds.length > 0 ? walletOfferIds : preferredWalletIds, preferredWalletIds);
  const defaultOfferUri = offerData?.offer_url || offerData?.credential_offer_uri || '';
  const offerUri = walletId ? walletOfferUris[walletId] || defaultOfferUri : defaultOfferUri;
  const transportArtifact = resolveWalletTransportArtifact(
    offerData?.transport_artifacts || offerData?.wallet_transport_artifacts,
    walletId || null,
  );
  const wallet = offerData?.wallet_registry?.[walletId] || offerData?.wallets_by_id?.[walletId] || null;
  const transport = transportArtifact || createCredentialOfferTransport({
    offerUri,
    wallet,
    platform,
    walletId,
  });

  return {
    walletId,
    offerUri,
    defaultOfferUri,
    transport,
  };
}

/**
 * @param {{ requestUri?: string, wallet?: Record<string, any> | null, platform?: string, walletId?: string }} [options]
 */
export function createPresentationTransport({ requestUri, wallet = null, platform = getPlatform(), walletId = '' } = {}) {
  const standardUri = buildOid4vpAuthorizationUri(requestUri);
  const walletUri = resolveWalletOpenUri({ wallet, innerUri: standardUri, platform, walletId });
  return {
    kind: 'oid4vp',
    platform,
    walletId: walletId || wallet?.id || '',
    innerUri: standardUri,
    qrUri: standardUri,
    copyUri: standardUri,
    openUri: walletUri || standardUri,
    method: walletUri ? TRANSPORT_METHODS.WALLET_LINK : TRANSPORT_METHODS.STANDARD_LINK,
  };
}

export function resolveTransportArtifact(artifacts, walletId) {
  if (!artifacts) return null;
  if (walletId && artifacts.wallets?.[walletId]) return artifacts.wallets[walletId];
  if (walletId && artifacts[walletId]) return artifacts[walletId];
  return artifacts.default || artifacts;
}
