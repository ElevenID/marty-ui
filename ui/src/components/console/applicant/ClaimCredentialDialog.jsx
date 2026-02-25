/**
 * ClaimCredentialDialog
 *
 * Applicant-facing dialog for claiming an approved credential into their wallet.
 *
 * Device-aware UX:
 *   Desktop → QR Code primary + web-wallet deep-link buttons + email-to-phone
 *   Mobile  → Wallet chooser with deep links primary + "Show QR" fallback
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
  Chip,
  TextField,
  Tab,
  Tabs,
} from '@mui/material';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import EmailIcon from '@mui/icons-material/Email';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';

import { getIssuanceOffer } from '../../../services/credentialsApi';
import QRCodeDisplay from '../../issuance/QRCodeDisplay';
import { isMobile, filterWalletsForDevice, openDeepLink } from '../../../utils/deviceDetection';

function TabPanel({ children, value, index }) {
  return (
    <Box role="tabpanel" hidden={value !== index} sx={{ pt: 2 }}>
      {value === index && children}
    </Box>
  );
}

export default function ClaimCredentialDialog({ open, onClose, applicationId }) {
  const [offer, setOffer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [notGenerated, setNotGenerated] = useState(false);
  const [tab, setTab] = useState(0); // 0 = wallets/QR, 1 = email
  const [copied, setCopied] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const [deepLinkFailed, setDeepLinkFailed] = useState(false);

  const mobile = isMobile();

  const loadOffer = useCallback(async () => {
    if (!applicationId) return;
    setLoading(true);
    setError(null);
    setNotGenerated(false);
    try {
      const data = await getIssuanceOffer(applicationId);
      setOffer(data);
    } catch (err) {
      const status = err?.response?.status ?? err?.status;
      if (status === 404) {
        setNotGenerated(true);
      } else {
        setError(err.message || 'Failed to load credential offer.');
      }
    } finally {
      setLoading(false);
    }
  }, [applicationId]);

  useEffect(() => {
    if (open) {
      setOffer(null);
      setNotGenerated(false);
      setError(null);
      setDeepLinkFailed(false);
      setEmailSent(false);
      setTab(0);
      loadOffer();
    }
  }, [open, applicationId]); // eslint-disable-line react-hooks/exhaustive-deps

  const isExpired = offer?.status === 'expired';
  const offerUrl = offer?.offer_url;
  const walletsForDevice = offer?.wallets ? filterWalletsForDevice(offer.wallets) : [];

  const handleCopy = async () => {
    if (!offerUrl) return;
    await navigator.clipboard.writeText(offerUrl).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleOpenWallet = async (wallet) => {
    setDeepLinkFailed(false);
    const opened = await openDeepLink(wallet.deep_link_url, 2500);
    if (!opened) {
      setDeepLinkFailed(true);
    }
  };

  const handleEmailSelf = () => {
    if (!emailValue || !offerUrl) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\nClick the link below or scan the QR code from your wallet app:\n\n${offerUrl}`
    );
    window.open(`mailto:${emailValue}?subject=${subject}&body=${body}`, '_blank');
    setEmailSent(true);
  };

  // ── Wallet buttons (shared between mobile and desktop) ──────────────────────
  const WalletButtons = () => (
    <Stack spacing={1.5}>
      {walletsForDevice.length > 0 ? (
        <>
          <Typography variant="caption" color="text.secondary">
            Choose your wallet:
          </Typography>
          {walletsForDevice.map((wallet) => (
            <Button
              key={wallet.id}
              variant="outlined"
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
              Open in {wallet.name}
            </Button>
          ))}
          {deepLinkFailed && (
            <Alert severity="info" sx={{ mt: 0.5 }}>
              Could not open the wallet. Make sure it&apos;s installed, or use the QR code tab.
            </Alert>
          )}
        </>
      ) : (
        <Button
          variant="outlined"
          fullWidth
          size="large"
          startIcon={<WalletIcon />}
          href={offerUrl}
        >
          Open in Wallet
        </Button>
      )}
    </Stack>
  );

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pb: 1 }}>
        <WalletIcon color="primary" />
        Add to Wallet
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {offer && !isExpired && (
          <Chip label="Ready" color="success" size="small" sx={{ ml: 'auto' }} />
        )}
      </DialogTitle>

      <DialogContent dividers>
        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        )}

        {!loading && notGenerated && (
          <Alert severity="info">
            Your wallet invite has not been generated yet. The issuer will notify you when
            your credential is ready to claim.
          </Alert>
        )}

        {!loading && error && (
          <Alert severity="error">{error}</Alert>
        )}

        {!loading && isExpired && (
          <Alert
            severity="warning"
            action={
              <Button size="small" color="inherit" startIcon={<RefreshIcon />} onClick={loadOffer}>
                Refresh
              </Button>
            }
          >
            This wallet invite has expired. Contact the issuer to regenerate it.
          </Alert>
        )}

        {!loading && offer && !isExpired && (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
              Your credential is approved and ready to add to your digital wallet.
            </Typography>

            {/* ── Tabs: [wallet icon] Wallet  |  [qr icon] QR Code  |  [email icon] Email ── */}
            <Tabs
              value={tab}
              onChange={(_, v) => setTab(v)}
              variant="fullWidth"
              sx={{ mb: 0, borderBottom: 1, borderColor: 'divider' }}
            >
              <Tab
                icon={<WalletIcon fontSize="small" />}
                iconPosition="start"
                label={mobile ? 'Wallet' : 'Wallets'}
                sx={{ minHeight: 40, fontSize: '0.8rem' }}
              />
              <Tab
                icon={<QrCode2Icon fontSize="small" />}
                iconPosition="start"
                label="QR Code"
                sx={{ minHeight: 40, fontSize: '0.8rem' }}
              />
              <Tab
                icon={<PhoneAndroidIcon fontSize="small" />}
                iconPosition="start"
                label="Email"
                sx={{ minHeight: 40, fontSize: '0.8rem' }}
              />
            </Tabs>

            {/* ── Tab 0: Wallet deep links ── */}
            <TabPanel value={tab} index={0}>
              <WalletButtons />
              <Divider sx={{ my: 1.5 }} />
              <Stack direction="row" spacing={1} justifyContent="center">
                <Button
                  size="small"
                  variant="text"
                  startIcon={copied ? <CheckCircleIcon color="success" /> : <ContentCopyIcon />}
                  onClick={handleCopy}
                  color={copied ? 'success' : 'primary'}
                >
                  {copied ? 'Copied!' : 'Copy offer link'}
                </Button>
              </Stack>
            </TabPanel>

            {/* ── Tab 1: QR Code ── */}
            <TabPanel value={tab} index={1}>
              <QRCodeDisplay
                offerUri={offerUrl}
                expiresAt={offer.expires_at}
                status="active"
                showDeepLink={false}
                showCopyLink={false}
                title="Scan with your wallet app"
                instructions={
                  mobile
                    ? 'Scan this QR code from another device with your wallet app.'
                    : 'Open your wallet app on your phone and tap Scan / Add credential.'
                }
                size={220}
              />
              <Stack direction="row" spacing={1} justifyContent="center" sx={{ mt: 1.5 }}>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={copied ? <CheckCircleIcon color="success" /> : <ContentCopyIcon />}
                  onClick={handleCopy}
                  color={copied ? 'success' : 'primary'}
                >
                  {copied ? 'Copied!' : 'Copy Link'}
                </Button>
              </Stack>
            </TabPanel>

            {/* ── Tab 2: Email to phone ── */}
            <TabPanel value={tab} index={2}>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Email the credential offer link to yourself to open on your phone.
              </Typography>
              <Stack direction="row" spacing={1} alignItems="flex-start" sx={{ mt: 1 }}>
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
                <Alert severity="success" sx={{ mt: 1.5 }}>
                  Email sent. Open the link on your phone to add the credential to your wallet.
                </Alert>
              )}
            </TabPanel>
          </>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 1.5 }}>
        {!loading && (notGenerated || error) && (
          <Button size="small" startIcon={<RefreshIcon />} onClick={loadOffer} sx={{ mr: 'auto' }}>
            Try again
          </Button>
        )}
        <Button onClick={onClose} variant="outlined" size="small" sx={{ ml: 'auto' }}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}

