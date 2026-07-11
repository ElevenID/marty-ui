/**
 * OID4VCIInviteDisplay
 *
 * Thin adapter that maps the offer payload from
 * `POST /v1/applications/{id}/issuance-offer` into props understood by
 * the generic QRCodeDisplay component.
 *
 * When the backend returns `credential_offer_uris` (a per-wallet map), a tab
 * selector is shown so the operator can present the correct QR for each wallet:
 *
 *   "Any Wallet"  — uses the default `offer_url` / `credential_offer_uri`
 *   "<WalletName>" — uses `credential_offer_uris[wallet_id]` for that wallet
 *
 * The SpruceID / Marty wallet tab is important because its offer URI points to
 * the `/org/{id}/spruce` issuer metadata endpoint which uses `spruce-vc+sd-jwt`
 * format — required by the SpruceID SDK.  The default endpoint uses `vc+sd-jwt`
 * which the SpruceID SDK cannot parse.
 *
 * Props:
 *   offerData     {Object}      — response from generateIssuanceOffer
 *   onRegenerate  {() => void}  — callback to regenerate the offer
 *   loading       {boolean}     — whether a regeneration is in progress
 *   title         {string}      — optional QR title override
 *   instructions  {string}      — optional instruction text override
 */

import { useEffect, useMemo, useState } from 'react';
import { Box, CircularProgress, Tab, Tabs } from '@mui/material';
import QRCodeDisplay from './QRCodeDisplay';
import {
  createCredentialOfferTransport,
  resolvePreferredWalletId,
  resolveWalletTransportArtifact,
} from '../../services/walletTransportService';
import { buildWalletOpenLink } from '../../services/walletRegistryApi';

/**
 * Fallback labels for known wallet IDs when no display_name comes from the
 * credential template.  Template-provided labels always take precedence.
 */
const FALLBACK_WALLET_LABELS = {
  // Legacy single-id style (old demo templates)
  marty:          'SpruceKit',
  spruce:         'SpruceKit',
  sprucekit:      'SpruceKit',
  // Registry-style IDs
  'wr-spruce-001': 'SpruceKit',
  'wr-marty-001':  'Marty Authenticator',
  'wr-default':    'Any OID4VCI Wallet',
  vcwallet:        'VC Wallet',
};

const walletLabel = (id, labels = {}) => labels[id] || FALLBACK_WALLET_LABELS[id] || id;

const DEFAULT_TAB = '__default__';
const PROTOCOL_ONLY_OPEN_LINK = /^(openid-credential-offer|openid4vp|haip-vci|haip-vp):/i;

function chooseWalletOpenUri(walletOpenUri, fallbackOpenLink) {
  if (!walletOpenUri) return fallbackOpenLink;
  if (
    fallbackOpenLink &&
    fallbackOpenLink !== walletOpenUri &&
    PROTOCOL_ONLY_OPEN_LINK.test(walletOpenUri) &&
    !PROTOCOL_ONLY_OPEN_LINK.test(fallbackOpenLink)
  ) {
    return fallbackOpenLink;
  }
  return walletOpenUri;
}

export default function OID4VCIInviteDisplay({
  offerData,
  onRegenerate,
  loading,
  showDeepLink = false,
  allowedWalletIds = null,
  showDefaultWalletTab = true,
  title,
  instructions,
}) {
  const rawOfferUris = useMemo(() => offerData?.credential_offer_uris || {}, [offerData]);
  const offerUris = useMemo(() => {
    if (!Array.isArray(allowedWalletIds)) return rawOfferUris;
    const allowed = new Set(allowedWalletIds.filter(Boolean));
    if (allowed.size === 0) return {};

    return Object.fromEntries(
      Object.entries(rawOfferUris).filter(([walletId]) => allowed.has(walletId)),
    );
  }, [allowedWalletIds, rawOfferUris]);
  const walletIds = useMemo(() => Object.keys(offerUris), [offerUris]);
  const initialWallet = walletIds.length > 0 ? resolvePreferredWalletId(walletIds, allowedWalletIds || []) : DEFAULT_TAB;
  const [selectedWallet, setSelectedWallet] = useState(initialWallet);
  const walletOptionsKey = walletIds.join('|');

  useEffect(() => {
    setSelectedWallet((current) => {
      if (current !== DEFAULT_TAB && walletIds.includes(current)) return current;
      if (current === DEFAULT_TAB && walletIds.length === 0) return current;
      return initialWallet;
    });
  }, [initialWallet, walletOptionsKey]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading && !offerData) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!offerData) return null;

  // Per-wallet offer URIs and template-provided labels from the backend
  const offerLabels = offerData.credential_offer_labels || {};
  const hasPerWalletUris = walletIds.length > 0;
  const defaultUri = offerData.offer_url || offerData.credential_offer_uri || '';
  const canShowDefaultTab = showDefaultWalletTab && Boolean(defaultUri);
  const showWalletTabs = hasPerWalletUris && (walletIds.length > 1 || canShowDefaultTab);

  // Resolve the URI to display for the currently selected tab
  const activeUri =
    selectedWallet === DEFAULT_TAB
      ? defaultUri
      : offerUris[selectedWallet] || defaultUri;
  const selectedTransportArtifact = resolveWalletTransportArtifact(
    offerData.transport_artifacts || offerData.wallet_transport_artifacts,
    selectedWallet === DEFAULT_TAB ? null : selectedWallet,
  );
  const transport = selectedTransportArtifact || createCredentialOfferTransport({
    offerUri: activeUri,
    wallet: offerData.wallet_registry?.[selectedWallet] || offerData.wallets_by_id?.[selectedWallet],
    walletId: selectedWallet === DEFAULT_TAB ? '' : selectedWallet,
  });
  const handleOpenLink = async (fallbackOpenLink) => {
    const walletId = selectedWallet === DEFAULT_TAB ? '' : selectedWallet;
    if (!walletId || !transport.innerUri) {
      window.location.href = fallbackOpenLink;
      return;
    }

    try {
      const response = await buildWalletOpenLink(walletId, {
        innerUri: transport.innerUri,
        platform: transport.platform,
      });
      window.location.href = chooseWalletOpenUri(response?.open_uri, fallbackOpenLink);
    } catch {
      window.location.href = fallbackOpenLink;
    }
  };

  const expiresAt = offerData.expires_at || null;
  const createdAt = offerData.created_at || null;

  // Derive status: the backend may return explicit status or we infer from expiry
  let status = offerData.status || 'active';
  if (status === 'expired' || (expiresAt && new Date(expiresAt) < new Date())) {
    status = 'expired';
  }

  return (
    <Box>
      {showWalletTabs && (
        <Tabs
          value={selectedWallet}
          onChange={(_, value) => setSelectedWallet(value)}
          sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
        >
          {walletIds.map((id) => (
            <Tab key={id} label={walletLabel(id, offerLabels)} value={id} />
          ))}
          {canShowDefaultTab && <Tab label="Other Wallets" value={DEFAULT_TAB} />}
        </Tabs>
      )}

      <QRCodeDisplay
        offerUri={activeUri}
        qrValue={transport.qrUri || transport.innerUri || activeUri}
        copyValue={transport.copyUri || transport.innerUri || activeUri}
        openLink={transport.openUri || transport.innerUri || activeUri}
        onOpenLink={handleOpenLink}
        expiresAt={expiresAt}
        createdAt={createdAt}
        status={status}
        onRefresh={onRegenerate}
        showDeepLink={showDeepLink}
        showCopyLink
        title={title || 'Scan to claim credential'}
        instructions={
          instructions ||
          (selectedWallet === DEFAULT_TAB
            ? 'Scan this QR code with any OID4VCI-compatible digital wallet to receive the credential.'
            : `Scan this QR code with the ${walletLabel(selectedWallet, offerLabels)} app to receive the credential.`)
        }
      />
    </Box>
  );
}
