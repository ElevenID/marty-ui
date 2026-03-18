/**
 * WalletOfferDialog
 *
 * Applicant-facing dialog to claim an approved/issued credential to their
 * digital wallet via OID4VCI pre-authorized code flow.
 *
 * Usage:
 *   <WalletOfferDialog
 *     open={open}
 *     onClose={() => setOpen(false)}
 *     applicationId={app.id}
 *     credentialName={app.credential_display_name}
 *   />
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  IconButton,
  Alert,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import RefreshIcon from '@mui/icons-material/Refresh';
import AccountBalanceWalletIcon from '@mui/icons-material/AccountBalanceWallet';
import OID4VCIInviteDisplay from '../issuance/OID4VCIInviteDisplay';
import { generateIssuanceOffer } from '../../services/credentialsApi';
import {
  createWalletOfferDialogState,
  loadWalletOfferDialog,
  resetWalletOfferDialogState,
  startWalletOfferDialogLoad,
} from '../../application/applications';

export default function WalletOfferDialog({ open, onClose, applicationId, credentialName }) {
  const [dialogState, setDialogState] = useState(() => createWalletOfferDialogState());
  const { offerData, loading, error } = dialogState;

  const fetchOffer = useCallback(async () => {
    if (!applicationId) return;
    setDialogState((currentState) => startWalletOfferDialogLoad(currentState));

    const nextState = await loadWalletOfferDialog({
      applicationId,
      generateIssuanceOffer,
    });

    setDialogState(nextState);
  }, [applicationId]);

  // Fetch when dialog opens
  useEffect(() => {
    if (open) {
      setDialogState(resetWalletOfferDialogState());
      fetchOffer();
    }
  }, [open, fetchOffer]);

  const handleClose = () => {
    setDialogState(resetWalletOfferDialogState());
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="xs"
      fullWidth
      PaperProps={{ sx: { borderRadius: 2 } }}
    >
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 6 }}>
        <AccountBalanceWalletIcon color="primary" />
        <Box>
          <Typography variant="h6" component="span">
            Add to Wallet
          </Typography>
          {credentialName && (
            <Typography variant="caption" display="block" color="text.secondary">
              {credentialName}
            </Typography>
          )}
        </Box>
        <IconButton
          onClick={handleClose}
          size="small"
          sx={{ position: 'absolute', right: 12, top: 12 }}
        >
          <CloseIcon fontSize="small" />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 1 }}>
        {error ? (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        ) : (
          <OID4VCIInviteDisplay
            offerData={offerData}
            onRegenerate={fetchOffer}
            loading={loading}
            title="Scan with your wallet"
            instructions="Open your digital wallet app and scan this QR code to add the credential to your wallet."
          />
        )}

        {!loading && !offerData && !error && (
          <Typography variant="body2" color="text.secondary" textAlign="center" py={2}>
            Generating your wallet offer…
          </Typography>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
        {error && (
          <Button
            startIcon={<RefreshIcon />}
            onClick={fetchOffer}
            variant="outlined"
            size="small"
          >
            Retry
          </Button>
        )}
        <Box sx={{ flex: 1 }} />
        <Button onClick={handleClose} variant="outlined" size="small">
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}
