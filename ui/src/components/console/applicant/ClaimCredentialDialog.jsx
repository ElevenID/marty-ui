/**
 * ClaimCredentialDialog
 *
 * Applicant-facing dialog for claiming an approved credential into their wallet.
 * Delegates QR code / wallet-tab display to OID4VCIInviteDisplay (same component
 * used by the org console) so the two stay in sync automatically.
 *
 * UX states:
 *   1. Ready       — offer generated, CTA enabled
 *   2. Awaiting    — QR / deep link shown, waiting for wallet scan
 *   3. Success     — credential added to wallet
 *   4. Error       — connection failed, with retry
 *   5. Expired     — offer expired, regenerate
 *
 * Props:
 *   open          {boolean}
 *   onClose       {() => void}
 *   applicationId {string}  — used to generate a fresh offer when expired
 *   offerData     {Object}  — pre-loaded offer: { offer_url, credential_offer_uris, expires_at }
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
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
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import EmailIcon from '@mui/icons-material/Email';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import RefreshIcon from '@mui/icons-material/Refresh';
import LockIcon from '@mui/icons-material/Lock';
import SettingsIcon from '@mui/icons-material/Settings';

import OID4VCIInviteDisplay from '../../issuance/OID4VCIInviteDisplay';
import { generateIssuanceOffer } from '../../../services/credentialsApi';
import { useAuth } from '../../../hooks/useAuth';
import useWalletPreferences from '../../../hooks/useWalletPreferences';
import { listWallets } from '../../../services/walletRegistryApi';

export default function ClaimCredentialDialog({ open, onClose, applicationId, offerData }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const { user } = useAuth();
  const { walletIds: preferredWallets } = useWalletPreferences(user?.user_id);
  const [registryWallets, setRegistryWallets] = useState([]);

  const [liveOffer, setLiveOffer] = useState(offerData);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [emailTab, setEmailTab] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);

  useEffect(() => {
    if (open) {
      setLiveOffer(offerData);
      setRefreshing(false);
      setError(null);
      setEmailTab(false);
      setEmailSent(false);
      setEmailValue(user?.email || '');
    }
  }, [open, offerData]); // eslint-disable-line react-hooks/exhaustive-deps

  // Load wallet registry once for label resolution
  useEffect(() => {
    listWallets(true)
      .then((w) => setRegistryWallets(Array.isArray(w) ? w : []))
      .catch(() => {});
  }, []);

  const handleRegenerate = useCallback(async () => {
    if (!applicationId) return;
    setRefreshing(true);
    setError(null);
    try {
      const fresh = await generateIssuanceOffer(applicationId);
      setLiveOffer(fresh);
    } catch (err) {
      setError(err?.message || 'Failed to generate wallet offer. Please try again.');
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

  // Build per-wallet offer data.
  // When the backend already provides per-wallet URIs, use them.
  // Otherwise, synthesise entries for the user's registered wallets (all
  // known wallets use the same openid-credential-offer:// scheme, so the
  // base URL works for every wallet).
  const enrichedOffer = useMemo(() => {
    if (!liveOffer) return liveOffer;
    const backendUris = liveOffer.credential_offer_uris;
    if (backendUris && Object.keys(backendUris).length > 0) return liveOffer;

    const baseUrl = liveOffer.offer_url || liveOffer.credential_offer_uri;
    if (!baseUrl) return liveOffer;

    // Build a label map from the registry
    const labelMap = {};
    for (const w of registryWallets) {
      labelMap[w.id] = w.name;
    }

    // Use user's preferred wallets if they've registered any
    const ids = preferredWallets.length > 0 ? preferredWallets : ['wr-marty-001'];
    const uris = {};
    const labels = { ...(liveOffer.credential_offer_labels || {}) };
    for (const id of ids) {
      uris[id] = baseUrl;
      if (!labels[id]) {
        labels[id] = labelMap[id] || id;
      }
    }

    return {
      ...liveOffer,
      credential_offer_uris: uris,
      credential_offer_labels: labels,
    };
  }, [liveOffer, preferredWallets, registryWallets]);

  const offerUrl = liveOffer?.offer_url || null;
  const isExpired = liveOffer?.status === 'expired';
  const notGenerated = liveOffer !== undefined && !offerUrl && !error;
  const showContent = !notGenerated && !!offerUrl && !isExpired && !error;

  // Deep link handler for mobile
  const handleOpenInWallet = () => {
    if (!offerUrl) return;
    let deepLinkUrl = offerUrl;
    if (!offerUrl.startsWith('openid-credential-offer://')) {
      deepLinkUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUrl)}`;
    }
    window.location.href = deepLinkUrl;
  };

  const handleEmailSelf = () => {
    const to = user?.email || emailValue;
    if (!to || !offerUrl) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\nOpen the link on your phone:\n\n${offerUrl}`
    );
    window.open(`mailto:${to}?subject=${subject}&body=${body}`, '_blank');
    setEmailSent(true);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pb: 1 }}>
        <WalletIcon color="primary" />
        Add to Wallet
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {showContent && <Chip label="Ready" color="success" size="small" sx={{ ml: 'auto' }} />}
        {error && <Chip label="Error" color="error" size="small" sx={{ ml: 'auto' }} />}
      </DialogTitle>

      <DialogContent dividers>
        {/* ── Error state with retry ── */}
        {error && (
          <Stack spacing={2} alignItems="center" sx={{ py: 2 }}>
            <Alert severity="error" sx={{ width: '100%' }}>{error}</Alert>
            <Button
              variant="contained"
              startIcon={<RefreshIcon />}
              onClick={handleRegenerate}
              disabled={refreshing}
            >
              {refreshing ? 'Retrying…' : 'Retry'}
            </Button>
          </Stack>
        )}

        {/* ── Not generated yet ── */}
        {notGenerated && (
          <Alert severity="info">
            Your wallet invite has not been generated yet. The issuer will notify you when
            your credential is ready to claim.
          </Alert>
        )}

        {/* ── Expired ── */}
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

        {/* ── Active content ── */}
        {showContent && (
          <>
            {/* Mobile: primary CTA is deep link */}
            {isMobile && (
              <Stack spacing={2} sx={{ mb: 2 }}>
                <Button
                  variant="contained"
                  size="large"
                  fullWidth
                  startIcon={<PhoneAndroidIcon />}
                  onClick={handleOpenInWallet}
                  sx={{ py: 1.5, fontSize: '1rem', borderRadius: 2 }}
                >
                  Open in Wallet App
                </Button>
                <Typography variant="caption" color="text.secondary" textAlign="center">
                  Your wallet app will open to receive this credential.
                </Typography>
              </Stack>
            )}

            {/* QR code (primary on desktop, secondary on mobile) */}
            <OID4VCIInviteDisplay
              offerData={enrichedOffer}
              onRegenerate={applicationId ? handleRegenerate : undefined}
              loading={refreshing}
              showDeepLink={!isMobile}
              title={isMobile ? 'Or scan with another device' : 'Scan with your wallet app'}
              instructions={
                isMobile
                  ? 'If you prefer to use a wallet on a different device, scan this QR code.'
                  : undefined
              }
            />

            {/* Nudge to register wallets if none selected */}
            {preferredWallets.length === 0 && (
              <Alert
                severity="info"
                icon={<SettingsIcon fontSize="small" />}
                sx={{ mt: 1.5 }}
                action={
                  <Button
                    size="small"
                    href="/console/applicant/settings"
                    onClick={onClose}
                  >
                    Settings
                  </Button>
                }
              >
                Register your wallet apps in Settings to see wallet-specific tabs here.
              </Alert>
            )}

            {/* ── Email link ── */}
            {
              <>
                <Button
                  size="small"
                  variant="text"
                  color="inherit"
                  startIcon={<EmailIcon fontSize="small" />}
                  endIcon={emailTab ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  onClick={() => { setEmailTab((v) => !v); setEmailSent(false); }}
                  sx={{ textTransform: 'none', color: 'text.secondary', mt: 1 }}
                >
                  Email link
                </Button>
                <Collapse in={emailTab}>
                  <Box sx={{ pt: 1, pb: 0.5 }}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography
                        variant="body2"
                        sx={{
                          flex: 1,
                          px: 1.5,
                          py: 0.75,
                          bgcolor: 'action.hover',
                          borderRadius: 1,
                          color: 'text.primary',
                          fontFamily: 'monospace',
                          fontSize: '0.8rem',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {user?.email || '—'}
                      </Typography>
                      <Button
                        variant="contained"
                        size="small"
                        startIcon={emailSent ? <CheckCircleIcon /> : <EmailIcon />}
                        onClick={handleEmailSelf}
                        disabled={!(user?.email) || emailSent}
                        color={emailSent ? 'success' : 'primary'}
                      >
                        {emailSent ? 'Sent!' : 'Send'}
                      </Button>
                    </Stack>
                    {emailSent && (
                      <Alert severity="success" sx={{ mt: 1 }}>
                        Email sent — open the link on your phone to add the credential to your wallet.
                      </Alert>
                    )}
                  </Box>
                </Collapse>
              </>
            }

            {/* ── Trust signals ── */}
            <Box sx={{ mt: 2, pt: 1.5, borderTop: 1, borderColor: 'divider' }}>
              <Stack direction="row" spacing={0.5} alignItems="center" justifyContent="center" sx={{ mb: 0.5 }}>
                <LockIcon sx={{ fontSize: 14, color: 'text.secondary' }} />
                <Typography variant="caption" color="text.secondary">
                  Secure issuance via OpenID4VCI
                </Typography>
              </Stack>
              <Typography variant="caption" color="text.secondary" display="block" textAlign="center">
                Your credential is cryptographically signed and stored in your wallet, not our database.
              </Typography>
            </Box>
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
