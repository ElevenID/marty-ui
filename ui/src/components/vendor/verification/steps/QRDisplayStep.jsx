import { useState, useEffect, useRef } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Alert,
  Button,
  Chip,
  Divider,
  Paper,
  Stack,
} from '@mui/material';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassTopIcon from '@mui/icons-material/HourglassTop';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import { getVerificationFlowInstance, getVerificationResult } from '../../../../services/zkVerificationApi';
import {
  DEFAULT_DC_API_PROTOCOL,
  formatDigitalCredentialError,
  runOpenId4VpDigitalCredentialFlow,
  supportsDigitalCredentials,
} from '../../../../services/digitalCredentialsApi';
import { createPresentationTransport } from '../../../../services/walletTransportService';
import { isOid4vpUri } from '../../../../services/credentialLinkUtils';
import { openDeepLink } from '../../../../utils/deviceDetection';
import VerificationResultSummary, { extractPresentationRejection, PresentationAttemptFeedback, verificationSessionId } from '../VerificationResultSummary';
import Oid4vpQrCode from '../Oid4vpQrCode';

const POLL_INTERVAL_MS = 3000;
const TERMINAL_STATUSES = ['completed', 'failed', 'expired', 'cancelled'];

const STATUS_CONFIG = {
  pending: { label: 'Waiting for wallet', color: 'warning', icon: <HourglassTopIcon fontSize="small" /> },
  completed: { label: 'Verified', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
  failed: { label: 'Failed', color: 'error', icon: <ErrorIcon fontSize="small" /> },
  expired: { label: 'Expired', color: 'default', icon: <ErrorIcon fontSize="small" /> },
  cancelled: { label: 'Cancelled', color: 'default', icon: <ErrorIcon fontSize="small" /> },
};

function normalizeSessionStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['passed', 'completed', 'verified'].includes(value)) return 'completed';
  if (['failed', 'denied'].includes(value)) return 'failed';
  if (value === 'expired') return 'expired';
  if (['cancelled', 'canceled'].includes(value)) return 'cancelled';
  return 'pending';
}

export function isApprovedVerificationResult(result) {
  return String(result?.status || '').toLowerCase() === 'completed'
    && String(result?.result || '').toLowerCase() === 'passed'
    && String(result?.decision || '').toLowerCase() === 'allow';
}

function QRDisplayStep({ session, onComplete }) {
  const [status, setStatus] = useState(normalizeSessionStatus(session?.status));
  const [result, setResult] = useState(null);
  const [attempt, setAttempt] = useState(() => extractPresentationRejection(session));
  const [error, setError] = useState(null);
  const [walletBusy, setWalletBusy] = useState(false);
  const [dcApiAvailable, setDcApiAvailable] = useState(false);
  const pollRef = useRef(null);
  const generation = useRef(0);
  const walletGeneration = useRef(0);
  const activeStatus = useRef(status);
  activeStatus.current = status;
  const instanceId = verificationSessionId(session) || null;
  const activeInstance = useRef(instanceId);
  activeInstance.current = instanceId;

  const loadTerminalResult = async (isCurrent) => {
    const verified = await getVerificationResult(instanceId);
    if (!isCurrent() || activeInstance.current !== instanceId) return;
    if (verified?.instance_id !== instanceId) {
      throw new Error('Verification result did not match this session.');
    }
    setResult(verified);
    setAttempt(null);
    setStatus(isApprovedVerificationResult(verified) ? 'completed' : 'failed');
    if (onComplete) onComplete(verified);
  };

  useEffect(() => {
    walletGeneration.current += 1;
    setStatus(normalizeSessionStatus(session?.status));
    setResult(null);
    setAttempt(extractPresentationRejection(session));
    setError(null);
    setWalletBusy(false);
    return () => { walletGeneration.current += 1; };
  }, [instanceId]);

  useEffect(() => {
    if (TERMINAL_STATUSES.includes(status)) {
      walletGeneration.current += 1;
      setWalletBusy(false);
    }
  }, [status]);

  useEffect(() => {
    const current = ++generation.current;
    const isCurrent = () => generation.current === current;
    if (!instanceId) return;
    if (TERMINAL_STATUSES.includes(status)) return;

    let polling = false;
    pollRef.current = setInterval(async () => {
      if (polling) return;
      polling = true;
      try {
        const updated = await getVerificationFlowInstance(instanceId);
        if (!isCurrent()) return;
        if (verificationSessionId(updated) !== instanceId) return;
        const updatedStatus = normalizeSessionStatus(updated.status || updated.state);
        if (['expired', 'cancelled'].includes(updatedStatus)) {
          setStatus(updatedStatus);
          setAttempt(null);
          clearInterval(pollRef.current);
        } else if (TERMINAL_STATUSES.includes(updatedStatus)) {
          clearInterval(pollRef.current);
          setAttempt(null);
          await loadTerminalResult(isCurrent);
        } else {
          setStatus(updatedStatus);
          setAttempt(extractPresentationRejection(updated, session));
        }
      } catch (err) {
        if (!isCurrent()) return;
        setAttempt(null);
        setStatus('failed');
        setError(err.message || 'Could not load the verified result.');
        clearInterval(pollRef.current);
      } finally {
        polling = false;
      }
    }, POLL_INTERVAL_MS);

    return () => { generation.current += 1; clearInterval(pollRef.current); };
  }, [instanceId, status, onComplete]);

  useEffect(() => {
    let mounted = true;
    supportsDigitalCredentials(DEFAULT_DC_API_PROTOCOL).then((supported) => {
      if (mounted) setDcApiAvailable(supported);
    });
    return () => { mounted = false; };
  }, []);

  const statusCfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const requestUri = typeof session?.request_uri === 'string' ? session.request_uri.trim() : '';
  const qrValue = isOid4vpUri(session?.qr_code_data) ? session.qr_code_data.trim() : requestUri;
  const transport = createPresentationTransport({ requestUri: qrValue });
  const dcApiRequestUrl = session?.dc_api_request_url || (instanceId ? `/v1/flows/instances/${encodeURIComponent(instanceId)}/request?transport=dc_api` : '');
  const dcApiSubmitUrl = session?.dc_api_submit_url || (instanceId ? `/v1/flows/instances/${encodeURIComponent(instanceId)}/submit/dc-api` : '');

  const handleOpenWallet = async () => {
    const current = walletGeneration.current;
    const isCurrent = () => walletGeneration.current === current
      && activeInstance.current === instanceId && !TERMINAL_STATUSES.includes(activeStatus.current);
    setWalletBusy(true);
    setError(null);
    try {
      if (dcApiAvailable && dcApiRequestUrl && dcApiSubmitUrl) {
        const completed = await runOpenId4VpDigitalCredentialFlow({
          requestUrl: dcApiRequestUrl,
          submitUrl: dcApiSubmitUrl,
        });
        if (!isCurrent()) return;
        if (TERMINAL_STATUSES.includes(normalizeSessionStatus(completed.status || completed.result))) {
          await loadTerminalResult(isCurrent);
        }
        return;
      }

      const opened = await openDeepLink(transport.openUri);
      if (!isCurrent()) return;
      if (!opened) {
        setError('Wallet did not open. Use the QR code or copy the link instead.');
      }
    } catch (err) {
      if (isCurrent()) setError(formatDigitalCredentialError(err));
    } finally {
      if (isCurrent()) setWalletBusy(false);
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <QrCode2Icon color="primary" />
        <Typography variant="h6">Scan to Verify</Typography>
        <Chip
          data-testid="verification-session-status"
          data-status={status}
          size="small"
          label={statusCfg.label}
          color={statusCfg.color}
          icon={statusCfg.icon}
          sx={{ ml: 'auto' }}
        />
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {status === 'pending' && (
        <>
          <PresentationAttemptFeedback attempt={attempt} />
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Open the wallet on this device, or ask the wallet holder to scan the
            QR code with their identity wallet app to share the required credentials.
          </Typography>

          {qrValue && (
            <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
              <Button
                variant="contained"
                startIcon={walletBusy ? <CircularProgress size={14} color="inherit" /> : <PhoneAndroidIcon />}
                onClick={handleOpenWallet}
                data-testid="verification-open-wallet"
                disabled={walletBusy}
              >
                {dcApiAvailable ? 'Open Wallet Chooser' : 'Open Wallet'}
              </Button>
            </Stack>
          )}

          {qrValue ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  display: 'inline-block',
                  background: '#fff',
                }}
              >
                <Oid4vpQrCode value={qrValue} />
              </Paper>
            </Box>
          ) : (
            <Alert severity="error" sx={{ mb: 2 }}>
              The verification session did not return a wallet request. Close this session and try again.
            </Alert>
          )}

          {qrValue && (
            <>
              <Divider sx={{ my: 1 }} />
              <Typography variant="caption" color="text.secondary">
                Deep link:{' '}
                <Box
                  component="code"
                  sx={{ wordBreak: 'break-all', fontSize: '0.75rem' }}
                >
                  {requestUri}
                </Box>
              </Typography>
            </>
          )}

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 2 }}>
            <CircularProgress size={14} />
            <Typography variant="caption" color="text.secondary">
              Polling for wallet response every {POLL_INTERVAL_MS / 1000}s…
            </Typography>
          </Box>
        </>
      )}

      {status === 'completed' && result && (
        <Stack spacing={1.5}>
          <Alert severity="success" icon={<CheckCircleIcon />}>
            Verification successful.
          </Alert>
          <VerificationResultSummary session={{ ...result, status: 'completed', result }} />
        </Stack>
      )}

      {['failed', 'expired', 'cancelled'].includes(status) && (
        <Alert severity="error">
          {error || result?.decision_reason || (status === 'expired'
            ? 'The verification session expired before the wallet responded.'
            : status === 'cancelled' ? 'The verification session was cancelled.'
              : 'Verification failed. The wallet did not satisfy the policy requirements.')}
        </Alert>
      )}
    </Box>
  );
}

export default QRDisplayStep;
