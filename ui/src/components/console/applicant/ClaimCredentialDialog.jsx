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
  Card,
  CardContent,
  Collapse,
  Chip,
  Checkbox,
  CircularProgress,
  LinearProgress,
  Radio,
  Typography,
  useMediaQuery,
  useTheme,
  FormControlLabel,
} from '@mui/material';
import EmailIcon from '@mui/icons-material/Email';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import RefreshIcon from '@mui/icons-material/Refresh';
import LockIcon from '@mui/icons-material/Lock';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import OID4VCIInviteDisplay from '../../issuance/OID4VCIInviteDisplay';
import { generateIssuanceOffer } from '../../../services/credentialsApi';
import { useAuth } from '../../../hooks/useAuth';
import useWalletPreferences from '../../../hooks/useWalletPreferences';
import {
  ANY_OID4VCI_WALLET_ID,
  buildClaimWalletOptions,
  getWalletOfferDialogError,
  resolveClaimWalletDeliveryDestinationId,
  resolveClaimWalletSelection,
  selectedClaimWalletIds,
  walletSupportsBrowserLaunch,
} from '../../../application/applications';
import { buildWalletOpenLink, listWallets } from '../../../services/walletRegistryApi';
import {
  createCredentialOfferTransport,
  resolvePreferredCredentialOfferTransport,
} from '../../../services/walletTransportService';
import { listDeliveryDestinations } from '../../../services/deliveryDestinationsApi';

const ELEVENID_WALLET_DESTINATION_ID = 'dd-elevenid-wallet';
const COMPATIBLE_WALLET_DESTINATION_ID = 'dd-oid4vci-compatible-wallet';
const CANVAS_CREDENTIALS_DESTINATION_ID = 'dd-canvas-credentials-institutional';

export default function ClaimCredentialDialog({ open, onClose, applicationId, offerData, organizationId }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const { user } = useAuth();
  const { walletIds: preferredWallets, setWalletIds } = useWalletPreferences(user?.user_id);
  const [registryWallets, setRegistryWallets] = useState([]);
  const [deliveryDestinations, setDeliveryDestinations] = useState([]);
  const [destinationsLoading, setDestinationsLoading] = useState(false);
  const [destinationError, setDestinationError] = useState(null);
  const [selectedWalletId, setSelectedWalletId] = useState(ANY_OID4VCI_WALLET_ID);
  const [canvasConsent, setCanvasConsent] = useState(true);

  const [liveOffer, setLiveOffer] = useState(offerData);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [emailTab, setEmailTab] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const walletOptions = useMemo(() => buildClaimWalletOptions({ registryWallets }), [registryWallets]);
  const selectedWallet = useMemo(
    () => walletOptions.find((wallet) => wallet.id === selectedWalletId) || walletOptions[0] || null,
    [selectedWalletId, walletOptions],
  );
  const selectedWalletName = selectedWallet?.name || 'Any OID4VCI Wallet';
  const selectedWalletIdList = useMemo(() => selectedClaimWalletIds(selectedWalletId), [selectedWalletId]);
  const selectedWalletDestinationId = resolveClaimWalletDeliveryDestinationId(selectedWalletId, {
    compatibleDestinationId: COMPATIBLE_WALLET_DESTINATION_ID,
    elevenIdDestinationId: ELEVENID_WALLET_DESTINATION_ID,
  });

  const handleSelectWallet = useCallback((walletId) => {
    const nextWalletId = walletId || ANY_OID4VCI_WALLET_ID;
    setSelectedWalletId(nextWalletId);
    if (nextWalletId !== ANY_OID4VCI_WALLET_ID) {
      setWalletIds([nextWalletId]);
    }
  }, [setWalletIds]);

  useEffect(() => {
    if (open) {
      setLiveOffer(applicationId ? null : offerData);
      setRefreshing(false);
      setError(null);
      setEmailTab(false);
      setEmailSent(false);
      setEmailValue(user?.email || '');
      setCanvasConsent(true);
    }
  }, [open, applicationId, user?.email]); // eslint-disable-line react-hooks/exhaustive-deps -- keep active QR stable while parent data refreshes

  useEffect(() => {
    if (!open || walletOptions.length === 0) return;
    const nextSelection = resolveClaimWalletSelection({ preferredWallets, walletOptions });
    setSelectedWalletId((current) => {
      const currentStillAvailable = walletOptions.some((wallet) => wallet.id === current);
      const hasPreferredSelection = preferredWallets.some((walletId) => walletOptions.some((wallet) => wallet.id === walletId));
      if (!currentStillAvailable) return nextSelection;
      if (current === ANY_OID4VCI_WALLET_ID && hasPreferredSelection) return nextSelection;
      return current;
    });
  }, [open, preferredWallets, walletOptions]);

  // Load wallet registry once for label resolution
  useEffect(() => {
    listWallets(true)
      .then((w) => setRegistryWallets(Array.isArray(w) ? w : []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!open) return;
    const orgId = organizationId || offerData?.organization_id;
    if (!orgId) {
      setDeliveryDestinations([]);
      return;
    }
    let cancelled = false;
    setDestinationsLoading(true);
    setDestinationError(null);
    listDeliveryDestinations({ activeOnly: true, organizationId: orgId })
      .then((items) => {
        if (!cancelled) setDeliveryDestinations(Array.isArray(items) ? items : []);
      })
      .catch((err) => {
        if (!cancelled) {
          setDeliveryDestinations([]);
          setDestinationError(err?.message || 'Could not load delivery destinations.');
        }
      })
      .finally(() => {
        if (!cancelled) setDestinationsLoading(false);
      });
    return () => { cancelled = true; };
  }, [open, organizationId, offerData?.organization_id]);

  const canvasDestination = useMemo(() => (
    deliveryDestinations.find((destination) => (
      destination.id === CANVAS_CREDENTIALS_DESTINATION_ID
      || (destination.provider === 'canvas_credentials' && destination.mode === 'organization_mirror')
    )) || null
  ), [deliveryDestinations]);

  const canvasDestinationReady = Boolean(canvasDestination?.is_enabled !== false && canvasDestination);
  const canGenerateWalletOffer = true;

  const handleRegenerate = useCallback(async () => {
    if (!applicationId || !canGenerateWalletOffer) return;
    setRefreshing(true);
    setError(null);
    try {
      const selectedDestinationIds = [selectedWalletDestinationId];
      if (canvasConsent && canvasDestinationReady) {
        selectedDestinationIds.push(canvasDestination.id || CANVAS_CREDENTIALS_DESTINATION_ID);
      }
      const fresh = await generateIssuanceOffer(applicationId, {
        delivery_destination_ids: Array.from(new Set(selectedDestinationIds.filter(Boolean))),
        canvas_credentials_consent: Boolean(canvasConsent && canvasDestinationReady),
      });
      setLiveOffer(fresh);
    } catch (err) {
      setError(getWalletOfferDialogError(err));
    } finally {
      setRefreshing(false);
    }
  }, [applicationId, canGenerateWalletOffer, selectedWalletDestinationId, canvasConsent, canvasDestinationReady, canvasDestination]);

  // OID4VCI pre-authorized codes are single-use. A previous wallet attempt can
  // consume a code even when its offer has not expired, so mint a fresh offer on
  // every claim dialog open instead of trusting cached application metadata.
  useEffect(() => {
    if (!open || !applicationId || !canGenerateWalletOffer) return;
    handleRegenerate();
  }, [open, applicationId, canGenerateWalletOffer, handleRegenerate]);

  // Build per-wallet offer data.
  // Keep backend-provided wallet URIs, then synthesize the selected wallet from
  // the generic OID4VCI offer when the backend does not return that wallet.
  const enrichedOffer = useMemo(() => {
    if (!liveOffer) return liveOffer;

    // Build wallet maps from the registry for labels and fallback routing.
    const labelMap = {};
    const walletMap = {};
    for (const w of walletOptions) {
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

    const baseUrl = liveOffer.offer_url || liveOffer.credential_offer_uri;
    const uris = { ...(liveOffer.credential_offer_uris || {}) };
    const labels = { ...(liveOffer.credential_offer_labels || {}) };

    if (baseUrl) {
      for (const id of selectedWalletIdList) {
        if (!uris[id]) {
          uris[id] = baseUrl;
        }
        if (!labels[id]) {
          labels[id] = labelMap[id] || id;
        }
      }
    }

    return {
      ...liveOffer,
      credential_offer_uris: uris,
      credential_offer_labels: labels,
      wallet_registry: walletRegistry,
      wallets_by_id: walletsById,
    };
  }, [liveOffer, selectedWalletIdList, walletOptions]);

  const preferredTransport = useMemo(() => {
    if (selectedWalletId === ANY_OID4VCI_WALLET_ID) {
      const defaultOfferUri = enrichedOffer?.offer_url || enrichedOffer?.credential_offer_uri || '';
      return {
        walletId: '',
        offerUri: defaultOfferUri,
        defaultOfferUri,
        transport: createCredentialOfferTransport({ offerUri: defaultOfferUri }),
      };
    }

    return resolvePreferredCredentialOfferTransport({
      offerData: enrichedOffer,
      preferredWalletIds: selectedWalletIdList,
    });
  }, [enrichedOffer, selectedWalletId, selectedWalletIdList]);

  const offerUrl = liveOffer?.offer_url || null;
  const primaryOfferUrl = preferredTransport.offerUri || offerUrl;
  const isExpired = liveOffer?.status === 'expired';
  const loadingInitialOffer = canGenerateWalletOffer && (refreshing || (applicationId && liveOffer === null)) && !primaryOfferUrl && !error;
  const notGenerated = canGenerateWalletOffer && !loadingInitialOffer && liveOffer != null && !primaryOfferUrl && !error;
  const showContent = canGenerateWalletOffer && !loadingInitialOffer && !notGenerated && !!primaryOfferUrl && !isExpired && !error;

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
        Receive Credential
        <Chip label={selectedWalletName} color="primary" variant="outlined" size="small" sx={{ ml: 'auto' }} />
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {showContent && <Chip label="Ready" color="success" size="small" />}
        {error && <Chip label="Error" color="error" size="small" />}
      </DialogTitle>

      <DialogContent dividers>
        <Stack spacing={1.25} sx={{ mb: 2 }} data-testid="wallet-selector" role="radiogroup" aria-label="Choose wallet">
          {destinationsLoading && <LinearProgress />}
          {destinationError && <Alert severity="info">{destinationError}</Alert>}
          {walletOptions.map((option) => {
            const selected = option.id === selectedWalletId;
            const isCompatibleWallet = option.id === ANY_OID4VCI_WALLET_ID;
            const browserLaunch = walletSupportsBrowserLaunch(option);
            const platforms = Array.isArray(option.supported_platforms || option.platforms)
              ? (option.supported_platforms || option.platforms).slice(0, 3)
              : [];
            return (
              <Card
                key={option.id}
                variant="outlined"
                role="radio"
                tabIndex={0}
                aria-checked={selected}
                data-testid={`wallet-option-${option.id}`}
                onClick={() => handleSelectWallet(option.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    handleSelectWallet(option.id);
                  }
                }}
                sx={{
                  cursor: 'pointer',
                  borderColor: selected ? 'primary.main' : 'divider',
                  bgcolor: selected ? 'action.selected' : 'background.paper',
                }}
              >
                <CardContent sx={{ py: 1.25, '&:last-child': { pb: 1.25 } }}>
                  <Stack direction="row" spacing={1.25} alignItems="flex-start">
                    <Radio checked={selected} size="small" sx={{ p: 0.25, mt: 0.1 }} />
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                        <Typography variant="body2" fontWeight={700}>{option.name}</Typography>
                        <Chip
                          size="small"
                          icon={browserLaunch ? <OpenInNewIcon /> : <PhoneAndroidIcon />}
                          label={browserLaunch ? 'Browser' : 'Mobile'}
                          color={selected ? 'primary' : 'default'}
                          variant="outlined"
                        />
                        {isCompatibleWallet && <Chip size="small" label="OID4VCI" variant="outlined" />}
                        {platforms.map((platform) => (
                          <Chip key={`${option.id}-${platform}`} size="small" label={platform} variant="outlined" />
                        ))}
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        {option.description || 'Receive this credential with this wallet.'}
                      </Typography>
                    </Box>
                    {selected && <CheckCircleIcon color="primary" fontSize="small" />}
                  </Stack>
                </CardContent>
              </Card>
            );
          })}
        </Stack>

        {canvasDestinationReady && (
          <FormControlLabel
            sx={{ mb: 1.5, alignItems: 'flex-start' }}
            control={
              <Checkbox
                checked={canvasConsent}
                onChange={(event) => setCanvasConsent(event.target.checked)}
                size="small"
              />
            }
            label={
              <Box>
                <Typography variant="body2">Also show this badge in Canvas Credentials</Typography>
                <Typography variant="caption" color="text.secondary">
                  Your organization manages this destination; only the public badge verification view is published.
                </Typography>
              </Box>
            }
          />
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
        {canGenerateWalletOffer && error && (
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
        {canGenerateWalletOffer && isExpired && (
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
                  {selectedWalletId === ANY_OID4VCI_WALLET_ID ? 'Open Wallet' : `Open ${selectedWalletName}`}
                </Button>
                <Typography variant="caption" color="text.secondary" textAlign="center">
                  {selectedWalletId === ANY_OID4VCI_WALLET_ID
                    ? 'Your browser will hand this invite to a compatible wallet.'
                    : `${selectedWalletName} will open to receive this credential.`}
                </Typography>
              </Stack>
            )}

            {/* QR code (primary on desktop, secondary on mobile) */}
            <OID4VCIInviteDisplay
              offerData={enrichedOffer}
              onRegenerate={applicationId ? handleRegenerate : undefined}
              loading={refreshing}
              showDeepLink={!isMobile}
              allowedWalletIds={selectedWalletIdList.length > 0 ? selectedWalletIdList : null}
              showDefaultWalletTab={selectedWalletId === ANY_OID4VCI_WALLET_ID}
              title={
                isMobile
                  ? 'Or scan with another device'
                  : selectedWalletId === ANY_OID4VCI_WALLET_ID
                    ? 'Scan with your wallet app'
                    : `Scan with ${selectedWalletName}`
              }
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
