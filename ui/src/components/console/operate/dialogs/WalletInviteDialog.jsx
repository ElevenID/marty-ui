/**
 * WalletInviteDialog
 *
 * Admin-facing dialog opened after an application is Approved.
 * Shows the QR code, copy link, per-wallet deep links, and email invite options.
 *
 * Props:
 *   open           {boolean}
 *   onClose        {() => void}
 *   offerData      {object|null}  — response from POST /v1/applications/{id}/issuance-offer
 *   loading        {boolean}
 *   onRegenerate   {() => void}   — callback to re-call the generate offer API
 */

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Divider,
  Stack,
  IconButton,
  Tooltip,
  Chip,
  Alert,
  CircularProgress,
  Tab,
  Tabs,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import EmailIcon from '@mui/icons-material/Email';
import RefreshIcon from '@mui/icons-material/Refresh';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

import QRCodeDisplay from '../../../issuance/QRCodeDisplay';

function TabPanel({ children, value, index }) {
  return (
    <Box role="tabpanel" hidden={value !== index} sx={{ pt: 2 }}>
      {value === index && children}
    </Box>
  );
}

export default function WalletInviteDialog({
  open,
  onClose,
  offerData,
  loading,
  onRegenerate,
}) {
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState(false);

  const isExpired = offerData?.status === 'expired';
  const offerUrl = offerData?.offer_url;
  const wallets = offerData?.wallets || [];
  const emailPayload = offerData?.email_payload;
  const expiresAt = offerData?.expires_at;

  const handleCopy = async () => {
    if (!offerUrl) return;
    try {
      await navigator.clipboard.writeText(offerUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  const handleEmailInvite = () => {
    if (!emailPayload) return;
    const mailtoUrl = `mailto:?subject=${encodeURIComponent(emailPayload.subject)}&body=${encodeURIComponent(emailPayload.body)}`;
    window.open(mailtoUrl, '_blank');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <WalletIcon color="primary" />
        Generate Wallet Invite
        {isExpired && (
          <Chip label="Expired" color="error" size="small" sx={{ ml: 'auto' }} />
        )}
      </DialogTitle>

      <DialogContent dividers>
        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        )}

        {!loading && !offerData && (
          <Alert severity="error">
            Failed to generate offer. Please try again.
          </Alert>
        )}

        {!loading && offerData && (
          <>
            {isExpired && (
              <Alert
                severity="warning"
                sx={{ mb: 2 }}
                action={
                  <Button size="small" startIcon={<RefreshIcon />} onClick={onRegenerate}>
                    Regenerate
                  </Button>
                }
              >
                This offer has expired. Regenerate to issue a new one.
              </Alert>
            )}

            <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tab icon={<QrCode2Icon fontSize="small" />} label="QR Code" iconPosition="start" />
              {wallets.length > 0 && (
                <Tab icon={<WalletIcon fontSize="small" />} label="Wallets" iconPosition="start" />
              )}
              <Tab icon={<EmailIcon fontSize="small" />} label="Email" iconPosition="start" />
            </Tabs>

            {/* ── QR Code Tab ── */}
            <TabPanel value={tab} index={0}>
              <QRCodeDisplay
                offerUri={offerUrl}
                expiresAt={expiresAt}
                status={isExpired ? 'expired' : 'active'}
                onRefresh={onRegenerate}
                showDeepLink={false}
                showCopyLink={false}
                title="Scan to add credential to wallet"
                instructions="Have the applicant scan this QR code with their wallet app."
              />
              <Stack direction="row" spacing={1} sx={{ mt: 2 }} justifyContent="center">
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={copied ? <CheckCircleIcon color="success" /> : <ContentCopyIcon />}
                  onClick={handleCopy}
                  color={copied ? 'success' : 'primary'}
                >
                  {copied ? 'Copied!' : 'Copy Link'}
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<EmailIcon />}
                  onClick={() => setTab(wallets.length > 0 ? 2 : 1)}
                >
                  Email to Applicant
                </Button>
              </Stack>
            </TabPanel>

            {/* ── Wallets Tab ── */}
            {wallets.length > 0 && (
              <TabPanel value={tab} index={1}>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Share the credential offer link directly via a supported wallet.
                </Typography>
                <Stack spacing={1}>
                  {wallets.map((wallet) => (
                    <Button
                      key={wallet.id}
                      variant="outlined"
                      fullWidth
                      startIcon={
                        wallet.logo_url ? (
                          <Box
                            component="img"
                            src={wallet.logo_url}
                            alt={wallet.name}
                            sx={{ width: 20, height: 20, objectFit: 'contain' }}
                          />
                        ) : (
                          <WalletIcon />
                        )
                      }
                      endIcon={<OpenInNewIcon fontSize="small" />}
                      href={wallet.deep_link_url}
                      target="_blank"
                      rel="noreferrer"
                      disabled={isExpired}
                      sx={{ justifyContent: 'flex-start' }}
                    >
                      Open in {wallet.name}
                      {wallet.platforms?.length > 0 && (
                        <Typography variant="caption" color="text.secondary" sx={{ ml: 'auto' }}>
                          {wallet.platforms.join(' · ')}
                        </Typography>
                      )}
                    </Button>
                  ))}
                </Stack>
                <Divider sx={{ mt: 2, mb: 1 }} />
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={copied ? <CheckCircleIcon color="success" /> : <ContentCopyIcon />}
                  onClick={handleCopy}
                  color={copied ? 'success' : 'primary'}
                  fullWidth
                >
                  {copied ? 'Copied!' : 'Copy Universal Link'}
                </Button>
              </TabPanel>
            )}

            {/* ── Email Tab ── */}
            <TabPanel value={tab} index={wallets.length > 0 ? 2 : 1}>
              <Typography variant="body2" color="text.secondary" paragraph>
                Send the credential offer to the applicant via email.
              </Typography>
              {emailPayload && (
                <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                    <strong>Subject:</strong> {emailPayload.subject}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ whiteSpace: 'pre-line' }}>
                    <strong>Body:</strong><br />
                    {emailPayload.body}
                  </Typography>
                </Box>
              )}
              <Button
                variant="contained"
                fullWidth
                startIcon={<EmailIcon />}
                onClick={handleEmailInvite}
                disabled={isExpired || !emailPayload}
              >
                Open Email Client
              </Button>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', textAlign: 'center', mt: 1 }}>
                Opens your default mail client with the invite pre-filled.
              </Typography>
            </TabPanel>
          </>
        )}
      </DialogContent>

      <DialogActions sx={{ justifyContent: 'space-between', px: 3, py: 1.5 }}>
        {onRegenerate && offerData && (
          <Tooltip title="Create a fresh offer (e.g. if expired or lost)">
            <Button
              startIcon={<RefreshIcon />}
              onClick={onRegenerate}
              size="small"
              color="secondary"
              disabled={loading}
            >
              Regenerate
            </Button>
          </Tooltip>
        )}
        <Button onClick={onClose} variant="outlined" size="small" sx={{ ml: 'auto' }}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}
