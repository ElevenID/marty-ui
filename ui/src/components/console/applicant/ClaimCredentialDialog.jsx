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

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
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
  CircularProgress,
  Radio,
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
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import OID4VCIInviteDisplay from '../../issuance/OID4VCIInviteDisplay';
import { generateIssuanceOffer, normalizeApplicationOffer } from '../../../services/credentialsApi';
import { getApplication } from '../../../services/applicantApi';
import { useAuth } from '../../../hooks/useAuth';
import useWalletPreferences from '../../../hooks/useWalletPreferences';
import useWalletOpenLink from '../../../hooks/useWalletOpenLink';
import {
  ANY_OID4VCI_WALLET_ID,
  buildClaimWalletOptions,
  getWalletOfferDialogError,
  resolveClaimWalletSelection,
  selectedClaimWalletIds,
  walletSupportsBrowserLaunch,
} from '../../../application/applications';
import { listWallets } from '../../../services/walletRegistryApi';
import {
  createCredentialOfferTransport,
  resolvePreferredCredentialOfferTransport,
} from '../../../services/walletTransportService';
const EMPTY_ITEMS = [];
const TERMINAL_CLAIM_STATES = new Set(['CLAIMED', 'EXPIRED', 'BLOCKED']);

export default function ClaimCredentialDialog({ open, onClose, applicationId, offerData, organizationId, generateOffer = generateIssuanceOffer, readApplication = getApplication }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const { user } = useAuth();
  const { walletIds: preferredWallets, setWalletIds } = useWalletPreferences(user?.user_id);
  const resolvedOrganizationId = organizationId || offerData?.organization_id || null;
  const scopeKey = JSON.stringify([applicationId || null, resolvedOrganizationId, user?.user_id || null]);
  const [registry, setRegistry] = useState(null);
  const registryWallets = registry?.scopeKey === scopeKey ? registry.items : EMPTY_ITEMS;
  const [walletSelection, setWalletSelection] = useState(null);

  const [preloadedOffer, setPreloadedOffer] = useState(offerData);
  const [offerAttempt, setOfferAttempt] = useState(0);
  const [offerRequest, setOfferRequest] = useState(null);
  const pendingOffers = useRef(new Map());
  const [emailTab, setEmailTab] = useState(false);
  const [emailValue, setEmailValue] = useState('');
  const [emailDraftRequested, setEmailDraftRequested] = useState(false);
  const walletOptions = useMemo(() => buildClaimWalletOptions({ registryWallets }), [registryWallets]);
  const selectedWalletId = walletSelection?.scopeKey === scopeKey && walletOptions.some((wallet) => wallet.id === walletSelection.id)
    ? walletSelection.id
    : resolveClaimWalletSelection({ preferredWallets, walletOptions });
  const selectedWallet = useMemo(
    () => walletOptions.find((wallet) => wallet.id === selectedWalletId) || walletOptions[0] || null,
    [selectedWalletId, walletOptions],
  );
  const selectedWalletName = selectedWallet?.name || 'Any OID4VCI Wallet';
  const selectedWalletIdList = useMemo(() => selectedClaimWalletIds(selectedWalletId), [selectedWalletId]);
  const handleSelectWallet = useCallback((walletId) => {
    const nextWalletId = walletId || ANY_OID4VCI_WALLET_ID;
    setWalletSelection({ scopeKey, id: nextWalletId });
    if (nextWalletId !== ANY_OID4VCI_WALLET_ID) {
      setWalletIds([nextWalletId]);
    }
  }, [setWalletIds, scopeKey]);

  useEffect(() => {
    if (open) {
      setPreloadedOffer(applicationId ? null : offerData);
      setEmailTab(false);
      setEmailDraftRequested(false);
      setEmailValue(user?.email || '');
    } else {
      setWalletSelection(null);
    }
  }, [open, scopeKey, user?.email]); // eslint-disable-line react-hooks/exhaustive-deps -- keep active QR stable while parent data refreshes

  // Load the global catalogue plus overrides for the active organization.
  useEffect(() => {
    if (!open) {
      setRegistry(null);
      return;
    }
    let active = true;
    listWallets(true, resolvedOrganizationId)
      .then((items) => {
        if (active) setRegistry({ scopeKey, items: Array.isArray(items) ? items : [] });
      })
      .catch(() => {
        if (active) setRegistry({ scopeKey, items: [] });
      });
    return () => { active = false; };
  }, [open, resolvedOrganizationId, scopeKey]);

  const canGenerateWalletOffer = registry?.scopeKey === scopeKey;
  const offerKey = JSON.stringify([scopeKey, offerAttempt]);
  const currentOffer = offerRequest?.key === offerKey ? offerRequest : null;
  const liveOffer = applicationId ? (canGenerateWalletOffer ? currentOffer?.data || null : null) : preloadedOffer;
  const refreshing = Boolean(applicationId && open && canGenerateWalletOffer && (!currentOffer || currentOffer.status === 'loading'));
  const error = currentOffer?.error || null;
  const handleRegenerate = useCallback(() => setOfferAttempt((attempt) => attempt + 1), []);

  // The Rust claim endpoint owns offer reuse and renewal. Wallet selection only
  // chooses a link/transport; the endpoint does not support holder destination or
  // Canvas mirror options. Reopening this dialog shares an in-flight request for
  // the same application/organization/holder, then uses the server's current offer.
  useEffect(() => {
    if (!open) {
      setOfferRequest(null);
      return;
    }
    if (!applicationId || !canGenerateWalletOffer) return;
    let active = true;
    setOfferRequest({ key: offerKey, status: 'loading' });
    let request = pendingOffers.current.get(scopeKey);
    if (!request) {
      request = generateOffer(applicationId).finally(() => {
        if (pendingOffers.current.get(scopeKey) === request) pendingOffers.current.delete(scopeKey);
      });
      pendingOffers.current.set(scopeKey, request);
    }
    request.then((data) => {
      if (active) setOfferRequest({ key: offerKey, status: 'ready', data });
    }).catch((err) => {
      if (active) setOfferRequest({ key: offerKey, status: 'error', error: getWalletOfferDialogError(err) });
    });
    return () => { active = false; };
  }, [open, applicationId, canGenerateWalletOffer, offerKey, scopeKey, generateOffer]);

  // A wallet can finish on another device without closing this dialog. Observe
  // the authenticated application projection; browser return and polling never
  // request issuance. Keep one read active and discard work from an old scope.
  useEffect(() => {
    if (!open || !applicationId || currentOffer?.status !== 'ready') return;
    let active = true;
    let reading = false;
    let timer;
    let terminal = TERMINAL_CLAIM_STATES.has(String(currentOffer.data?.claim_state || '').toUpperCase());
    const schedule = () => {
      clearTimeout(timer);
      if (active && !terminal) timer = setTimeout(refreshStatus, 2000);
    };
    async function refreshStatus() {
      if (!active || reading) return;
      if (document.visibilityState === 'hidden') { schedule(); return; }
      clearTimeout(timer);
      reading = true;
      try {
        const application = await readApplication(applicationId);
        if (!active) return;
        if (application?.id !== applicationId
          || (resolvedOrganizationId && application.organization_id !== resolvedOrganizationId)) {
          throw new Error('Claim status does not belong to the current application');
        }
        terminal = TERMINAL_CLAIM_STATES.has(String(application.claim_state || '').toUpperCase());
        setOfferRequest({ key: offerKey, status: 'ready', data: normalizeApplicationOffer(application) });
      } catch {
        if (active) {
          terminal = true;
          setOfferRequest({ key: offerKey, status: 'error', error: 'Could not confirm the current claim status. Try again.' });
        }
      } finally {
        reading = false;
        schedule();
      }
    }
    const onReturn = () => { if (document.visibilityState !== 'hidden') refreshStatus(); };
    window.addEventListener('focus', onReturn);
    document.addEventListener('visibilitychange', onReturn);
    schedule();
    return () => {
      active = false;
      clearTimeout(timer);
      window.removeEventListener('focus', onReturn);
      document.removeEventListener('visibilitychange', onReturn);
    };
  }, [open, applicationId, resolvedOrganizationId, offerKey, currentOffer?.status, readApplication]); // eslint-disable-line react-hooks/exhaustive-deps -- one read loop per offer attempt

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
  const isExpired = String(liveOffer?.status || '').toUpperCase() === 'EXPIRED'
    || String(liveOffer?.claim_state || '').toUpperCase() === 'EXPIRED';
  const isClaimed = String(liveOffer?.claim_state || '').toUpperCase() === 'CLAIMED';
  const isBlocked = String(liveOffer?.claim_state || '').toUpperCase() === 'BLOCKED';
  const loadingInitialOffer = Boolean(applicationId && (refreshing || liveOffer === null) && !primaryOfferUrl && !error);
  const notGenerated = !loadingInitialOffer && liveOffer != null && !primaryOfferUrl && !isExpired && !isClaimed && !isBlocked && !error;
  const showContent = !loadingInitialOffer && !notGenerated && !!primaryOfferUrl && !isExpired && !isClaimed && !isBlocked && !error;

  const { openingWallet, openWallet } = useWalletOpenLink({
    active: open && showContent,
    requestScopeKey: offerKey,
    walletId: preferredTransport.walletId,
    innerUri: preferredTransport.transport?.innerUri,
    platform: preferredTransport.transport?.platform,
    fallbackOpenLink: preferredTransport.transport?.openUri || preferredTransport.transport?.innerUri || primaryOfferUrl,
  });

  const handleEmailSelf = () => {
    const to = user?.email || emailValue;
    if (!to || !primaryOfferUrl) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\nOpen the link on your phone:\n\n${primaryOfferUrl}`
    );
    window.open(`mailto:${to}?subject=${subject}&body=${body}`, '_blank');
    setEmailDraftRequested(true);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="xs"
      fullWidth
      fullScreen={isMobile}
      data-testid="credential-claim-dialog"
      data-application-id={applicationId}
    >
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pb: 1 }}>
        <WalletIcon color="primary" />
        Receive Credential
        <Chip label={selectedWalletName} color="primary" variant="outlined" size="small" sx={{ ml: 'auto' }} />
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {showContent && <Chip label="Ready" color="success" size="small" />}
        {isClaimed && <Chip label="Claimed" color="success" size="small" />}
        {error && <Chip label="Error" color="error" size="small" />}
      </DialogTitle>

      <DialogContent dividers>
        <Stack spacing={1.25} sx={{ mb: 2 }} data-testid="wallet-selector" role="radiogroup" aria-label="Choose wallet">
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

        {loadingInitialOffer && (
          <Stack spacing={2} alignItems="center" sx={{ py: 4 }}>
            <CircularProgress />
            <Typography variant="body2" color="text.secondary" textAlign="center">
              Preparing your wallet invite...
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

        {isClaimed && <Alert severity="success">Your credential has been claimed. You can close this dialog.</Alert>}
        {isBlocked && <Alert severity="warning">{liveOffer.claim_blocker?.message || 'This credential cannot be claimed right now.'}</Alert>}

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
                  data-testid="wallet-open-link"
                  variant="contained"
                  size="large"
                  fullWidth
                  startIcon={<PhoneAndroidIcon />}
                  onClick={openWallet}
                  disabled={openingWallet}
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
              active={open && showContent}
              requestScopeKey={offerKey}
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
                  onClick={() => { setEmailTab((v) => !v); setEmailDraftRequested(false); }}
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
                        startIcon={emailDraftRequested ? <CheckCircleIcon /> : <EmailIcon />}
                        onClick={handleEmailSelf}
                        disabled={!(user?.email) || emailDraftRequested}
                        color={emailDraftRequested ? 'success' : 'primary'}
                      >
                        {emailDraftRequested ? 'Draft requested' : 'Open email draft'}
                      </Button>
                    </Stack>
                    {emailDraftRequested && (
                      <Alert severity="info" sx={{ mt: 1 }}>
                        Complete and send the message in your email app, then open the link on your phone.
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
                The issuer signs the credential before it is delivered to your wallet.
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
