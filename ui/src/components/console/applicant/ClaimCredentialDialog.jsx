/**
 * ClaimCredentialDialog
 *
 * Applicant-facing dialog for claiming an approved credential into their wallet.
 * Delegates QR code / wallet-tab display to OID4VCIInviteDisplay (same component
 * used by the org console) so the two stay in sync automatically.
 *
 * Props:
 *   open          {boolean}
 *   onClose       {() => void}
 *   applicationId {string}  — used to generate a fresh offer when expired
 *   offerData     {Object}  — pre-loaded offer: { offer_url, credential_offer_uris, expires_at }
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Stack,
  Alert,
  Collapse,
  Chip,
  TextField,
} from '@mui/material';
import EmailIcon from '@mui/icons-material/Email';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';

import OID4VCIInviteDisplay from '../../issuance/OID4VCIInviteDisplay';
import { generateIssuanceOffer } from '../../../services/credentialsApi';

export default function ClaimCredentialDialog({ open, onClose, applicationId, offerData }) {
  const [liveOffer, setLiveOffer] = useState(offerData);
  const [refreshing, setRefreshing] = useState(false);
  const [emailTab, setEmailTab] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);

  useEffect(() => {
    if (open) {
      setLiveOffer(offerData);
      setRefreshing(false);
      setEmailTab(false);
      setEmailSent(false);
      setEmailValue('');
    }
  }, [open, offerData]);

  const handleRegenerate = useCallback(async () => {
    if (!applicationId) return;
    setRefreshing(true);
    try {
      const fresh = await generateIssuanceOffer(applicationId);
      setLiveOffer(fresh);
    } catch {
      // leave existing offer in place; QRCodeDisplay will show error state
    } finally {
      setRefreshing(false);
    }
  }, [applicationId]);

  // Auto-regenerate on open when the offer is expired, close to expiring (< 5 min), or missing
  useEffect(() => {
    if (!open || !applicationId || refreshing) return;
    const url = offerData?.offer_url;
    const expiresAt = offerData?.expires_at;
    const expired = offerData?.status === 'expired';
    const nearlyExpired = expiresAt && (new Date(expiresAt) - Date.now()) < 5 * 60 * 1000;
    if (!url || expired || nearlyExpired) {
      handleRegenerate();
    }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const offerUrl = liveOffer?.offer_url || null;
  const isExpired = liveOffer?.status === 'expired';
  const notGenerated = liveOffer !== undefined && !offerUrl;
  const showContent = !notGenerated && !!offerUrl && !isExpired;

  const handleEmailSelf = () => {
    if (!emailValue || !offerUrl) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\nOpen the link on your phone:\n\n${offerUrl}`
    );
    window.open(`mailto:${emailValue}?subject=${subject}&body=${body}`, '_blank');
    setEmailSent(true);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pb: 1 }}>
        <WalletIcon color="primary" />
        Add to Wallet
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {showContent && <Chip label="Ready" color="success" size="small" sx={{ ml: 'auto' }} />}
      </DialogTitle>

      <DialogContent dividers>
        {notGenerated && (
          <Alert severity="info">
            Your wallet invite has not been generated yet. The issuer will notify you when
            your credential is ready to claim.
          </Alert>
        )}

        {isExpired && (
          <Alert
            severity="warning"
            action={
              applicationId ? (
                <Button size="small" onClick={handleRegenerate} disabled={refreshing}>
                  {refreshing ? 'Refreshing…' : 'Get new offer'}
                </Button>
              ) : undefined
            }
          >
            This wallet invite has expired.
          </Alert>
        )}

        {showContent && (
          <>
            <OID4VCIInviteDisplay
              offerData={liveOffer}
              onRegenerate={applicationId ? handleRegenerate : undefined}
              loading={refreshing}
              showDeepLink
              title="Scan with your wallet app"
              instructions="Open your wallet app on your phone and tap Scan / Add credential."
            />

            {/* ── Email offer link to phone ── */}
            <Button
              size="small"
              variant="text"
              color="inherit"
              startIcon={<EmailIcon fontSize="small" />}
              endIcon={emailTab ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              onClick={() => { setEmailTab((v) => !v); setEmailSent(false); }}
              sx={{ textTransform: 'none', color: 'text.secondary', mt: 1 }}
            >
              Email offer link to phone
            </Button>
            <Collapse in={emailTab}>
              <Box sx={{ pt: 1.5 }}>
                <Stack direction="row" spacing={1} alignItems="flex-start">
                  <TextField
                    size="small"
                    type="email"
                    placeholder="your@email.com"
                    value={emailValue}
                    onChange={(e) => setEmailValue(e.target.value)}
                    sx={{ flex: 1 }}
                    disabled={emailSent}
                    onKeyDown={(e) => e.key === 'Enter' && handleEmailSelf()}
                  />
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={emailSent ? <CheckCircleIcon /> : <EmailIcon />}
                    onClick={handleEmailSelf}
                    disabled={!emailValue || emailSent}
                    color={emailSent ? 'success' : 'primary'}
                  >
                    {emailSent ? 'Sent!' : 'Send'}
                  </Button>
                </Stack>
                {emailSent && (
                  <Alert severity="success" sx={{ mt: 1 }}>
                    Email sent — open the link on your phone to claim your credential.
                  </Alert>
                )}
              </Box>
            </Collapse>
          </>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 1.5 }}>
        <Button onClick={onClose} variant="outlined" size="small" sx={{ ml: 'auto' }}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}
