/**
 * OID4VCIInviteDisplay
 *
 * Thin adapter that maps the offer payload from
 * `POST /v1/applications/{id}/issuance-offer` into props understood by
 * the generic QRCodeDisplay component.
 *
 * Props:
 *   offerData     {Object}      — response from generateIssuanceOffer
 *   onRegenerate  {() => void}  — callback to regenerate the offer
 *   loading       {boolean}     — whether a regeneration is in progress
 *   title         {string}      — optional QR title override
 *   instructions  {string}      — optional instruction text override
 */

import { Box, CircularProgress } from '@mui/material';
import QRCodeDisplay from './QRCodeDisplay';

export default function OID4VCIInviteDisplay({ offerData, onRegenerate, loading, title, instructions }) {
  if (loading && !offerData) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!offerData) return null;

  // Map the application-issuance-offer response shape → QRCodeDisplay props
  const offerUri = offerData.offer_url || offerData.credential_offer_uri || '';
  const expiresAt = offerData.expires_at || null;
  const createdAt = offerData.created_at || null;

  // Derive status: the backend may return explicit status or we infer from expiry
  let status = offerData.status || 'active';
  if (status === 'expired' || (expiresAt && new Date(expiresAt) < new Date())) {
    status = 'expired';
  }

  return (
    <QRCodeDisplay
      offerUri={offerUri}
      expiresAt={expiresAt}
      createdAt={createdAt}
      status={status}
      onRefresh={onRegenerate}
      showDeepLink={false}
      showCopyLink
      title={title || 'Scan to claim credential'}
      instructions={instructions || 'Have the applicant scan this QR code with their digital wallet to receive the credential.'}
    />
  );
}
