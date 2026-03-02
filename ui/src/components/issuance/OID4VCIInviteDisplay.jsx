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

import { useState } from 'react';
import { Box, CircularProgress, Tab, Tabs } from '@mui/material';
import QRCodeDisplay from './QRCodeDisplay';

/** Map wallet_id values to human-readable tab labels. */
const WALLET_LABELS = {
  marty:     'SpruceKit',
  spruce:    'SpruceKit',
  sprucekit: 'SpruceKit',
  vcwallet:  'VC Wallet',
};

const walletLabel = (id) => WALLET_LABELS[id] || id;

const DEFAULT_TAB = '__default__';

export default function OID4VCIInviteDisplay({ offerData, onRegenerate, loading, title, instructions }) {
  // Default to the first wallet-specific tab when per-wallet URIs are available,
  // so the operator sees the correct wallet QR immediately without an extra click.
  const initialWallet = (() => {
    const ids = Object.keys(offerData?.credential_offer_uris || {});
    return ids.length > 0 ? ids[0] : DEFAULT_TAB;
  })();
  const [selectedWallet, setSelectedWallet] = useState(initialWallet);

  if (loading && !offerData) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!offerData) return null;

  // Per-wallet offer URIs from the backend (keyed by wallet_id)
  const offerUris = offerData.credential_offer_uris || {};
  const walletIds = Object.keys(offerUris);
  const hasPerWalletUris = walletIds.length > 0;

  // Resolve the URI to display for the currently selected tab
  const activeUri =
    selectedWallet === DEFAULT_TAB
      ? offerData.offer_url || offerData.credential_offer_uri || ''
      : offerUris[selectedWallet] || offerData.offer_url || offerData.credential_offer_uri || '';

  const expiresAt = offerData.expires_at || null;
  const createdAt = offerData.created_at || null;

  // Derive status: the backend may return explicit status or we infer from expiry
  let status = offerData.status || 'active';
  if (status === 'expired' || (expiresAt && new Date(expiresAt) < new Date())) {
    status = 'expired';
  }

  return (
    <Box>
      {hasPerWalletUris && (
        <Tabs
          value={selectedWallet}
          onChange={(_, value) => setSelectedWallet(value)}
          sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
        >
          {walletIds.map((id) => (
            <Tab key={id} label={walletLabel(id)} value={id} />
          ))}
          <Tab label="Other Wallets" value={DEFAULT_TAB} />
        </Tabs>
      )}

      <QRCodeDisplay
        offerUri={activeUri}
        expiresAt={expiresAt}
        createdAt={createdAt}
        status={status}
        onRefresh={onRegenerate}
        showDeepLink={false}
        showCopyLink
        title={title || 'Scan to claim credential'}
        instructions={
          instructions ||
          (selectedWallet === DEFAULT_TAB
            ? 'Have the applicant scan this QR code with any OID4VCI-compatible digital wallet to receive the credential.'
            : `Have the applicant scan this QR code with the ${walletLabel(selectedWallet)} app to receive the credential.`)
        }
      />
    </Box>
  );
}
