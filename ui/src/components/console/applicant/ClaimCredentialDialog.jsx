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
import { Link as RouterLink } from 'react-router-dom';
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
  CircularProgress,
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

import OID4VCIInviteDisplay from '../../issuance/OID4VCIInviteDisplay';
import { generateIssuanceOffer } from '../../../services/credentialsApi';
import { useAuth } from '../../../hooks/useAuth';
import useWalletPreferences from '../../../hooks/useWalletPreferences';
import { buildWalletOpenLink, listWallets } from '../../../services/walletRegistryApi';
import { resolvePreferredCredentialOfferTransport } from '../../../services/walletTransportService';

const APPLICANT_WALLET_SELECTION_SETTINGS_PATH = '/console/applicant/settings#wallet-selection';

export default function ClaimCredentialDialog({ open, onClose, applicationId, offerData }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const { user } = useAuth();
  const { walletIds: preferredWallets } = useWalletPreferences(user?.user_id);
  const hasRegisteredWallet = preferredWallets.length > 0;
  const [registryWallets, setRegistryWallets] = useState([]);

  const [liveOffer, setLiveOffer] = useState(offerData);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [emailTab, setEmailTab] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);

  useEffect(() => {
    if (open) {
      setLiveOffer(applicationId ? null : offerData);
      setRefreshing(false);
      setError(null);
      setEmailTab(false);
      setEmailSent(false);
      setEmailValue(user?.email || '');
    }
  }, [open, applicationId]); // eslint-disable-line react-hooks/exhaustive-deps -- keep active QR stable while parent data refreshes

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

  // OID4VCI pre-authorized codes are single-use. A previous wallet attempt can
  // consume a code even when its offer has not expired, so mint a fresh offer on
  // every claim dialog open instead of trusting cached application metadata.
  useEffect(() => {
    if (!open || !applicationId || !hasRegisteredWallet) return;
    handleRegenerate();
  }, [open, applicationId, hasRegisteredWallet, handleRegenerate]);

  // Build per-wallet offer data.
  // When the backend already provides per-wallet URIs, use them.
  // Otherwise, synthesise entries for the user's registered wallets (all
  // known wallets use the same openid-credential-offer:// scheme, so the
  // base URL works for every wallet).
  const enrichedOffer = useMemo(() => {
    if (!liveOffer) return liveOffer;
    const backendUris = liveOffer.credential_offer_uris;

    if (!hasRegisteredWallet) {
      return liveOffer;
    }

    // Build wallet maps from the registry for labels and fallback routing.
    const labelMap = {};
    const walletMap = {};
    for (const w of registryWallets) {
      walletMap[w.id] = w;
      labelMap[w.id] = w.name;
    }

    const walletRegistry = {
      ...(liveOffer.wallet_registry || {}),
      ...walletMap,
    };
    const walletsById = {
      ...(liveOffer.wallets_by_id || {}),
      ...walletMap,
    };

    if (backendUris && Object.keys(backendUris).length > 0) {
      return {
        ...liveOffer,
        wallet_registry: walletRegistry,
        wallets_by_id: walletsById,
      };
    }

    const baseUrl = liveOffer.offer_url || liveOffer.credential_offer_uri;
    if (!baseUrl) {
      return {
        ...liveOffer,
        wallet_registry: walletRegistry,
        wallets_by_id: walletsById,
      };
    }

    // Use user's preferred wallets if they've registered any
    const uris = {};
    const labels = { ...(liveOffer.credential_offer_labels || {}) };
    for (const id of preferredWallets) {
      uris[id] = baseUrl;
      if (!labels[id]) {
        labels[id] = labelMap[id] || id;
      }
    }

    return {
      ...liveOffer,
      credential_offer_uris: uris,
      credential_offer_labels: labels,
      wallet_registry: walletRegistry,
      wallets_by_id: walletsById,
    };
  }, [liveOffer, hasRegisteredWallet, preferredWallets, registryWallets]);

  const preferredTransport = useMemo(
    () => resolvePreferredCredentialOfferTransport({ offerData: enrichedOffer, preferredWalletIds: preferredWallets }),
    [enrichedOffer, preferredWallets],
  );

  const offerUrl = liveOffer?.offer_url || null;
  const primaryOfferUrl = preferredTransport.offerUri || offerUrl;
  const isExpired = liveOffer?.status === 'expired';
  const loadingInitialOffer = hasRegisteredWallet && (refreshing || (applicationId && liveOffer === null)) && !primaryOfferUrl && !error;
  const notGenerated = hasRegisteredWallet && !loadingInitialOffer && liveOffer != null && !primaryOfferUrl && !error;
  const showWalletRegistrationGuard = !hasRegisteredWallet;
  const showContent = hasRegisteredWallet && !loadingInitialOffer && !notGenerated && !!primaryOfferUrl && !isExpired && !error;

  // Deep link handler for mobile
  const handleOpenInWallet = async () => {
    if (!primaryOfferUrl) return;

    const fallbackOpenLink = preferredTransport.transport?.openUri || preferredTransport.transport?.innerUri || primaryOfferUrl;

    if (!preferredTransport.walletId || !preferredTransport.transport?.innerUri) {
      window.location.href = fallbackOpenLink;
      return;
    }

    try {
      const response = await buildWalletOpenLink(preferredTransport.walletId, {
        innerUri: preferredTransport.transport.innerUri,
        platform: preferredTransport.transport.platform,
      });
      window.location.href = response?.open_uri || fallbackOpenLink;
    } catch {
      window.location.href = fallbackOpenLink;
    }
  };

  const handleEmailSelf = () => {
    const to = user?.email || emailValue;
    if (!to || !primaryOfferUrl) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\nOpen the link on your phone:\n\n${primaryOfferUrl}`
    );
    window.open(`mailto:${to}?subject=${subject}&body=${body}`, '_blank');
    setEmailSent(true);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pb: 1 }}>
        <WalletIcon color="primary" />
        Add to Wallet
        {showWalletRegistrationGuard && <Chip label="Wallet required" color="warning" size="small" sx={{ ml: 'auto' }} />}
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {showContent && <Chip label="Ready" color="success" size="small" sx={{ ml: 'auto' }} />}
        {error && <Chip label="Error" color="error" size="small" sx={{ ml: 'auto' }} />}
      </DialogTitle>

      <DialogContent dividers>
        {showWalletRegistrationGuard && (
          <Stack spacing={2} sx={{ py: 1 }} data-testid="wallet-registration-guard">
            <Alert severity="warning" icon={<WalletIcon fontSize="small" />}>
              Select a wallet app before you can receive this credential.
            </Alert>
            <Typography variant="body2" color="text.secondary">
              Choose the wallet app you use in Settings, then come back here to receive the
              credential. Right now, wallet selection is the registration step.
            </Typography>
            <Button
              component={RouterLink}
              to={APPLICANT_WALLET_SELECTION_SETTINGS_PATH}
              variant="contained"
              startIcon={<WalletIcon />}
              onClick={onClose}
              sx={{ alignSelf: 'flex-start' }}
            >
              Choose Wallet
            </Button>
          </Stack>
        )}

        {loadingInitialOffer && (
          <Stack spacing={2} alignItems="center" sx={{ py: 4 }}>
            <CircularProgress />
            <Typography variant="body2" color="text.secondary" textAlign="center">
              Generating a fresh wallet invite...
            </Typography>
          </Stack>
        )}
        {/* ── Error state with retry ── */}
        {hasRegisteredWallet && error && (
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
        {hasRegisteredWallet && isExpired && (
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
              allowedWalletIds={hasRegisteredWallet ? preferredWallets : null}
              showDefaultWalletTab={!hasRegisteredWallet}
              title={isMobile ? 'Or scan with another device' : 'Scan with your wallet app'}
              instructions={
                isMobile
                  ? 'If you prefer to use a wallet on a different device, scan this QR code.'
                  : undefined
              }
            />

            {/* Nudge to register wallets if none selected */}
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
