/**
 * OID4VCIInviteDisplay
 *
 * Thin adapter that maps the offer payload from
 * `POST /v1/me/applications/{id}/claim` into props understood by
 * the generic QRCodeDisplay component.
 *
 * When the backend returns `credential_offer_uris` (a per-wallet map), a tab
 * selector is shown so the operator can present the correct QR for each wallet:
 *
 *   "Any Wallet"  — uses the default `offer_url` / `credential_offer_uri`
 *   "<WalletName>" — uses `credential_offer_uris[wallet_id]` for that wallet
 *
 * The SpruceID / Marty wallet tab is important because its offer URI points to
 * the standard organization-scoped OID4VCI issuer metadata endpoint
 * format — required by the SpruceID SDK.  The default endpoint uses `vc+sd-jwt`
 * which the SpruceID SDK cannot parse.
 *
 * Props:
 *   offerData     {Object}      — response from generateIssuanceOffer
 *   onRegenerate  {() => void}  — callback to regenerate the offer
 *   loading       {boolean}     — whether a regeneration is in progress
 *   title         {string}      — optional QR title override
 *   instructions  {string}      — optional instruction text override
 *   active        {boolean}     — disables handoff as soon as the containing view closes
 *   requestScopeKey {string}    — stable identity for the containing application/offer attempt
 */

import { useEffect, useMemo, useState } from 'react';
import { Box, CircularProgress, Tab, Tabs } from '@mui/material';
import QRCodeDisplay from './QRCodeDisplay';
import {
  createCredentialOfferTransport,
  resolvePreferredWalletId,
  resolveWalletTransportArtifact,
} from '../../services/walletTransportService';
import useWalletOpenLink from '../../hooks/useWalletOpenLink';

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
export default function OID4VCIInviteDisplay({
  offerData,
  onRegenerate,
  loading,
  showDeepLink = false,
  allowedWalletIds = null,
  showDefaultWalletTab = true,
  title,
  instructions,
  active = true,
  requestScopeKey = null,
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

  // Per-wallet offer URIs and template-provided labels from the backend
  const offerLabels = offerData?.credential_offer_labels || {};
  const hasPerWalletUris = walletIds.length > 0;
  const defaultUri = offerData?.offer_url || offerData?.credential_offer_uri || '';
  const canShowDefaultTab = showDefaultWalletTab && Boolean(defaultUri);
  const showWalletTabs = hasPerWalletUris && (walletIds.length > 1 || canShowDefaultTab);
  // A changed allowlist is effective during this render; do not briefly route
  // through the previous wallet while the tab-selection effect catches up.
  const activeWallet = selectedWallet === DEFAULT_TAB && canShowDefaultTab
    ? DEFAULT_TAB : walletIds.includes(selectedWallet) ? selectedWallet : initialWallet;

  // Resolve the URI to display for the currently selected tab
  const activeUri =
    activeWallet === DEFAULT_TAB
      ? defaultUri
      : offerUris[activeWallet] || defaultUri;
  const selectedTransportArtifact = resolveWalletTransportArtifact(
    offerData?.transport_artifacts || offerData?.wallet_transport_artifacts,
    activeWallet === DEFAULT_TAB ? null : activeWallet,
  );
  const transport = selectedTransportArtifact || createCredentialOfferTransport({
    offerUri: activeUri,
    wallet: offerData?.wallet_registry?.[activeWallet] || offerData?.wallets_by_id?.[activeWallet],
    walletId: activeWallet === DEFAULT_TAB ? '' : activeWallet,
  });
  const { openingWallet, openWallet } = useWalletOpenLink({
    active: active && Boolean(offerData) && !loading,
    requestScopeKey,
    walletId: activeWallet === DEFAULT_TAB ? '' : activeWallet,
    innerUri: transport.innerUri,
    platform: transport.platform,
    fallbackOpenLink: transport.openUri || transport.innerUri || activeUri,
  });

  if (loading && !offerData) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
        <CircularProgress />
      </Box>
    );
  }
  if (!offerData) return null;

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
          value={activeWallet}
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
        onOpenLink={openWallet}
        openingWallet={openingWallet || !active || loading}
        expiresAt={expiresAt}
        createdAt={createdAt}
        status={status}
        onRefresh={onRegenerate}
        showDeepLink={showDeepLink}
        showCopyLink
        title={title || 'Scan to claim credential'}
        instructions={
          instructions ||
          (activeWallet === DEFAULT_TAB
            ? 'Scan this QR code with any OID4VCI-compatible digital wallet to receive the credential.'
            : `Scan this QR code with the ${walletLabel(activeWallet, offerLabels)} app to receive the credential.`)
        }
      />
    </Box>
  );
}
