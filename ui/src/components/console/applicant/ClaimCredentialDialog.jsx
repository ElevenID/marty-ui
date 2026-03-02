/**
 * ClaimCredentialDialog
 *
 * Applicant-facing dialog for claiming an approved credential into their wallet.
 *
 * Device-aware UX:
 *   Desktop → Wallet-tab selector (per wallet QR codes, similar to org console)
 *   Mobile  → Deep-link buttons per wallet (tap to open app), QR as collapsible fallback
 *
 * Props:
 *   open           {boolean}
 *   onClose        {() => void}
 *   applicationId  {string}   — used as fallback if offerData not provided
 *   offerData      {Object}   — pre-loaded offer: { offer_url, credential_offer_uris, expires_at }
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
  Collapse,
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
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { apiClient } from '../../../services/api';
import QRCodeDisplay from '../../issuance/QRCodeDisplay';
import { isMobile, openDeepLink } from '../../../utils/deviceDetection';

/** Human-readable names and optional branding for known wallet IDs */
const WALLET_META = {
  marty: { label: 'SpruceKit', color: '#2563eb' },
  spruce: { label: 'SpruceKit', color: '#2563eb' },
  sprucekit: { label: 'SpruceKit', color: '#2563eb' },
};

const walletLabel = (id) => WALLET_META[id]?.label || id;

const GENERIC_ID = '__generic__';

/** Build a flat wallet list from credential_offer_uris + a generic fallback */
function buildWallets(offerUris, offerUrl) {
  const specific = Object.entries(offerUris || {}).map(([id, uri]) => ({
    id,
    label: walletLabel(id),
    uri,
  }));
  const result = [...specific];
  if (offerUrl) {
    result.push({ id: GENERIC_ID, label: specific.length ? 'Other Wallets' : 'Open in Wallet', uri: offerUrl });
  }
  return result;
}

/** Fetch the offer via the UI's applicant API (fallback when offerData not passed as prop) */
async function fetchOffer(applicationId) {
  const response = await apiClient.get(`/v1/applications/${applicationId}/issuance-offer`);
  return response.data;
}

export default function ClaimCredentialDialog({ open, onClose, applicationId, offerData }) {
  const [apiOffer, setApiOffer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Wallet-selector state
  const [selectedWallet, setSelectedWallet] = useState(null);
  const [deepLinkFailed, setDeepLinkFailed] = useState(false);
  const [showQrOnMobile, setShowQrOnMobile] = useState(false);

  // Email state
  const [emailTab, setEmailTab] = useState(false); // toggle email section
  const [emailValue, setEmailValue] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const [copied, setCopied] = useState(false);

  const mobile = isMobile();

  // ── Resolve the active offer ────────────────────────────────────────────────
  // Prefer the pre-loaded offerData prop; fall back to API-fetched data.
  const activeOffer = offerData ?? apiOffer;
  const offerUrl = activeOffer?.offer_url || null;
  const offerUris = activeOffer?.credential_offer_uris || {};
  const isExpired = activeOffer?.status === 'expired';
  const notGenerated = !loading && !error && activeOffer !== null && !offerUrl;

  // Build wallet list once offer is resolved
  const wallets = buildWallets(offerUris, offerUrl);
  const resolvedWallet = selectedWallet ?? wallets[0]?.id ?? null;
  const activeUri = wallets.find((w) => w.id === resolvedWallet)?.uri ?? offerUrl ?? '';

  // ── Load from API when offerData prop is not provided ──────────────────────
  const loadOffer = useCallback(async () => {
    if (!applicationId || offerData !== undefined) return; // prop takes precedence
    setLoading(true);
    setError(null);
    setApiOffer(null);
    try {
      const data = await fetchOffer(applicationId);
      setApiOffer(data);
    } catch (err) {
      const status = err?.response?.status ?? err?.status;
      if (status === 404) {
        setApiOffer({}); // empty = not generated
      } else {
        setError(err.message || 'Failed to load credential offer.');
      }
    } finally {
      setLoading(false);
    }
  }, [applicationId, offerData]);

  useEffect(() => {
    if (open) {
      setApiOffer(null);
      setError(null);
      setSelectedWallet(null);
      setDeepLinkFailed(false);
      setShowQrOnMobile(false);
      setEmailTab(false);
      setEmailSent(false);
      setCopied(false);
      loadOffer();
    }
  }, [open, applicationId]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Handlers ───────────────────────────────────────────────────────────────
  const handleCopy = async () => {
    if (!activeUri) return;
    await navigator.clipboard.writeText(activeUri).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleOpenDeepLink = async (uri) => {
    setDeepLinkFailed(false);
    const opened = await openDeepLink(uri, 2500);
    if (!opened) setDeepLinkFailed(true);
  };

  const handleEmailSelf = () => {
    if (!emailValue || !activeUri) return;
    const subject = encodeURIComponent('Your credential is ready');
    const body = encodeURIComponent(
      `Your credential is ready to add to your wallet.\n\nOpen the link on your phone:\n\n${activeUri}`
    );
    window.open(`mailto:${emailValue}?subject=${subject}&body=${body}`, '_blank');
    setEmailSent(true);
  };

  // ── Derived loading state ──────────────────────────────────────────────────
  // When offerData prop is supplied we never show a loading spinner.
  const showLoading = loading && !offerData;
  const showContent = !showLoading && !error && !notGenerated && !!offerUrl && !isExpired;

  // ── Render helpers ─────────────────────────────────────────────────────────

  /** Wallet tab bar (desktop + mobile tab row) */
  const WalletTabs = () =>
    wallets.length > 1 ? (
      <Tabs
        value={resolvedWallet}
        onChange={(_, v) => { setSelectedWallet(v); setDeepLinkFailed(false); setShowQrOnMobile(false); }}
        sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}
        variant="scrollable"
        scrollButtons="auto"
      >
        {wallets.map((w) => (
          <Tab
            key={w.id}
            value={w.id}
            label={w.label}
            sx={{ minHeight: 40, fontSize: '0.8rem', textTransform: 'none' }}
          />
        ))}
      </Tabs>
    ) : null;

  /** Desktop body: QR code (with optional wallet tabs above) */
  const DesktopQr = () => (
    <>
      <WalletTabs />
      <QRCodeDisplay
        offerUri={activeUri}
        expiresAt={activeOffer?.expires_at}
        status="active"
        showDeepLink={false}
        showCopyLink={false}
        title={
          resolvedWallet && resolvedWallet !== GENERIC_ID
            ? `Scan with ${wallets.find((w) => w.id === resolvedWallet)?.label}`
            : 'Scan with your wallet app'
        }
        instructions={`Open your ${
          resolvedWallet && resolvedWallet !== GENERIC_ID
            ? wallets.find((w) => w.id === resolvedWallet)?.label + ' app'
            : 'wallet app'
        } on your phone and tap Scan / Add credential.`}
        size={230}
      />
    </>
  );

  /** Mobile body: deep-link buttons + optional QR toggle */
  const MobileDeepLinks = () => (
    <>
      <WalletTabs />
      <Stack spacing={1.5} sx={{ mb: 1.5 }}>
        <Typography variant="caption" color="text.secondary">
          Tap to open in your wallet app:
        </Typography>
        <Button
          variant="contained"
          size="large"
          fullWidth
          startIcon={<WalletIcon />}
          endIcon={<OpenInNewIcon fontSize="small" />}
          onClick={() => handleOpenDeepLink(activeUri)}
          sx={{ justifyContent: 'space-between', textTransform: 'none' }}
        >
          Open in{' '}
          {resolvedWallet && resolvedWallet !== GENERIC_ID
            ? wallets.find((w) => w.id === resolvedWallet)?.label
            : 'Wallet'}
        </Button>
        {deepLinkFailed && (
          <Alert severity="info" sx={{ py: 0.5 }}>
            Could not open the app. Make sure it&apos;s installed, or use the QR code below.
          </Alert>
        )}
      </Stack>

      {/* QR code toggle (fallback for mobile) */}
      <Button
        size="small"
        variant="text"
        color="inherit"
        startIcon={showQrOnMobile ? <ExpandLessIcon /> : <QrCode2Icon />}
        endIcon={showQrOnMobile ? null : <ExpandMoreIcon />}
        onClick={() => setShowQrOnMobile((v) => !v)}
        sx={{ textTransform: 'none', color: 'text.secondary', mb: 0.5 }}
      >
        {showQrOnMobile ? 'Hide QR Code' : 'Show QR Code instead'}
      </Button>
      <Collapse in={showQrOnMobile}>
        <QRCodeDisplay
          offerUri={activeUri}
          expiresAt={activeOffer?.expires_at}
          status="active"
          showDeepLink={false}
          showCopyLink={false}
          title="Scan from another device"
          instructions="Scan this QR code from a desktop device."
          size={200}
        />
      </Collapse>
    </>
  );

  /** Email to phone section (bottom of both layouts) */
  const EmailSection = () => (
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
  );

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pb: 1 }}>
        <WalletIcon color="primary" />
        Add to Wallet
        {isExpired && <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />}
        {showContent && (
          <Chip label="Ready" color="success" size="small" sx={{ ml: 'auto' }} />
        )}
      </DialogTitle>

      <DialogContent dividers>
        {/* ── Loading ── */}
        {showLoading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        )}

        {/* ── Not yet generated ── */}
        {!showLoading && notGenerated && (
          <Alert severity="info">
            Your wallet invite has not been generated yet. The issuer will notify you when
            your credential is ready to claim.
          </Alert>
        )}

        {/* ── Error ── */}
        {!showLoading && error && (
          <Alert severity="error">{error}</Alert>
        )}

        {/* ── Expired ── */}
        {!showLoading && isExpired && (
          <Alert severity="warning">
            This wallet invite has expired. Contact the issuer to regenerate it.
          </Alert>
        )}

        {/* ── Active offer ── */}
        {showContent && (
          <>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Your credential is approved and ready to add to your digital wallet.
            </Typography>

            {mobile ? <MobileDeepLinks /> : <DesktopQr />}

            {/* ── Copy link ── */}
            <Stack direction="row" justifyContent="center" sx={{ mt: 1.5 }}>
              <Button
                size="small"
                variant="text"
                startIcon={copied ? <CheckCircleIcon color="success" /> : <ContentCopyIcon />}
                onClick={handleCopy}
                color={copied ? 'success' : 'primary'}
                sx={{ textTransform: 'none' }}
              >
                {copied ? 'Link copied!' : 'Copy offer link'}
              </Button>
            </Stack>

            <EmailSection />
          </>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 1.5 }}>
        {!showLoading && (notGenerated || error) && !offerData && (
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

