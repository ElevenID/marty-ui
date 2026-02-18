/**
 * ClaimCredentialDialog
 *
 * Applicant-facing dialog for claiming an approved credential into their wallet.
 *
 * Device-aware UX:
 *   Desktop → QR Code + Email-to-phone flow
 *   Mobile  → Wallet chooser with deep links
 *
 * Props:
 *   open           {boolean}
 *   onClose        {() => void}
 *   applicationId  {string}
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Stack,
  Alert,
  CircularProgress,
  Divider,
  IconButton,
  Tooltip,
  Chip,
  TextField,
} from '@mui/material';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import EmailIcon from '@mui/icons-material/Email';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import RefreshIcon from '@mui/icons-material/Refresh';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';

import { apiClient } from '../../../services/api';
import QRCodeDisplay from '../../issuance/QRCodeDisplay';
import { isMobile, filterWalletsForDevice, openDeepLink } from '../../../utils/deviceDetection';

async function fetchOffer(applicationId) {
  const response = await apiClient.get(`/v1/applications/${applicationId}/issuance-offer`);
  return response.data;
}

export default function ClaimCredentialDialog({ open, onClose, applicationId }) {
  const [offer, setOffer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showQrFallback, setShowQrFallback] = useState(false);
  const [copied, setCopied] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const [deepLinkFailed, setDeepLinkFailed] = useState(false);

  const mobile = isMobile();

  const loadOffer = useCallback(async () => {
    if (!applicationId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchOffer(applicationId);
      setOffer(data);
    } catch (err) {
      const status = err?.response?.status;
      if (status === 404) {
        setError('Your wallet invite has not been generated yet. Please contact the issuer.');
      } else {
        setError(err.message || 'Failed to load credential offer.');
      }
    } finally {
      setLoading(false);
    }
  }, [applicationId]);

  useEffect(() => {
    if (open) {
      loadOffer();
      setShowQrFallback(false);
      setDeepLinkFailed(false);
      setEmailSent(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, applicationId]);

  const isExpired = offer?.status === 'expired';
  const offerUrl = offer?.offer_url;
  const walletsForDevice = offer?.wallets ? filterWalletsForDevice(offer.wallets) : [];

  const handleCopy = async () => {
    if (!offerUrl) return;
    await navigator.clipboard.writeText(offerUrl).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenWallet = async (wallet) => {
    const opened = await openDeepLink(wallet.deep_link_url, 2500);
    if (!opened) {
      setDeepLinkFailed(true);
      setShowQrFallback(true);
    }
  };

  const handleEmailSelf = () => {
    if (!emailValue || !offerUrl) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\n${offerUrl}`
    );
    window.open(`mailto:${emailValue}?subject=${subject}&body=${body}`, '_blank');
    setEmailSent(true);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <WalletIcon color="primary" />
        Add to Wallet
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
      </DialogTitle>

      <DialogContent dividers>
        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        )}

        {!loading && error && (
          <Alert severity={error.includes('not been generated') ? 'info' : 'error'}>
            {error}
          </Alert>
        )}

        {!loading && isExpired && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Your wallet invite has expired. Please contact the issuer to generate a new one.
          </Alert>
        )}

        {!loading && offer && !isExpired && (
          <>
            <Typography variant="body1" fontWeight="medium" gutterBottom>
              Your credential is ready.
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Add it to your digital wallet to use it.
            </Typography>

            {/* ── MOBILE: wallet chooser + deep links ── */}
            {mobile && !showQrFallback && (
              <Stack spacing={1.5}>
                {walletsForDevice.length > 0 ? (
                  <>
                    <Typography variant="caption" color="text.secondary">
                      Choose your wallet:
                    </Typography>
                    {walletsForDevice.map((wallet) => (
                      <Button
                        key={wallet.id}
                        variant="contained"
                        fullWidth
                        size="large"
                        startIcon={
                          wallet.logo_url ? (
                            <Box
                              component="img"
                              src={wallet.logo_url}
                              alt={wallet.name}
                              sx={{ width: 22, height: 22, objectFit: 'contain' }}
                            />
                          ) : (
                            <WalletIcon />
                          )
                        }
                        onClick={() => handleOpenWallet(wallet)}
                        sx={{ justifyContent: 'flex-start' }}
                      >
                        Add to {wallet.name}
                      </Button>
                    ))}
                  </>
                ) : (
                  <Button
                    variant="contained"
                    fullWidth
                    size="large"
                    startIcon={<WalletIcon />}
                    href={offerUrl}
                  >
                    Add to Wallet
                  </Button>
                )}

                {deepLinkFailed && (
                  <Alert severity="info" sx={{ mt: 1 }}>
                    Having trouble? Your wallet app may not be installed.
                  </Alert>
                )}

                <Divider sx={{ my: 1 }} />
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<QrCode2Icon />}
                  onClick={() => setShowQrFallback(true)}
                  fullWidth
                >
                  Show QR instead
                </Button>
              </Stack>
            )}

            {/* ── DESKTOP or QR fallback ── */}
            {(!mobile || showQrFallback) && (
              <Stack spacing={2}>
                <QRCodeDisplay
                  offerUri={offerUrl}
                  expiresAt={offer.expires_at}
                  status="active"
                  showDeepLink={false}
                  showCopyLink={false}
                  title="Scan with your wallet app"
                  instructions={
                    mobile
                      ? 'Scan this QR code from another device to add the credential.'
                      : 'Open your wallet app on your phone and scan this QR code.'
                  }
                  size={220}
                />

                <Stack direction="row" spacing={1} justifyContent="center">
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={copied ? <CheckCircleIcon color="success" /> : <ContentCopyIcon />}
                    onClick={handleCopy}
                    color={copied ? 'success' : 'primary'}
                  >
                    {copied ? 'Copied!' : 'Copy Link'}
                  </Button>
                </Stack>

                {/* Email to phone */}
                <Divider />
                <Typography variant="caption" color="text.secondary" gutterBottom>
                  <EmailIcon fontSize="inherit" sx={{ mr: 0.5, verticalAlign: 'middle' }} />
                  Email to my phone
                </Typography>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <TextField
                    size="small"
                    type="email"
                    placeholder="your@email.com"
                    value={emailValue}
                    onChange={(e) => setEmailValue(e.target.value)}
                    sx={{ flex: 1 }}
                    disabled={emailSent}
                  />
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleEmailSelf}
                    disabled={!emailValue || emailSent}
                  >
                    {emailSent ? 'Sent!' : 'Send'}
                  </Button>
                </Box>
              </Stack>
            )}
          </>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 1.5 }}>
        {showQrFallback && mobile && (
          <Button size="small" onClick={() => setShowQrFallback(false)} sx={{ mr: 'auto' }}>
            ← Back to Wallets
          </Button>
        )}
        <Button onClick={onClose} variant="outlined" size="small" sx={{ ml: 'auto' }}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}
