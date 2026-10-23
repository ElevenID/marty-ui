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
import { openDeepLink } from '../../../../utils/deviceDetection';
import VerificationResultSummary from '../VerificationResultSummary';
import Oid4vpQrCode from '../Oid4vpQrCode';

const POLL_INTERVAL_MS = 3000;
const TERMINAL_STATUSES = ['completed', 'failed', 'expired'];

const STATUS_CONFIG = {
  pending: { label: 'Waiting for wallet', color: 'warning', icon: <HourglassTopIcon fontSize="small" /> },
  completed: { label: 'Verified', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
  failed: { label: 'Failed', color: 'error', icon: <ErrorIcon fontSize="small" /> },
  expired: { label: 'Expired', color: 'default', icon: <ErrorIcon fontSize="small" /> },
};

function normalizeSessionStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['passed', 'completed', 'verified'].includes(value)) return 'completed';
  if (['failed', 'denied'].includes(value)) return 'failed';
  if (value === 'expired') return 'expired';
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
  const [error, setError] = useState(null);
  const [walletBusy, setWalletBusy] = useState(false);
  const [dcApiAvailable, setDcApiAvailable] = useState(false);
  const pollRef = useRef(null);
  const instanceId = session?.instance_id || session?.flow_instance_id || session?.id || null;

  const loadTerminalResult = async () => {
    const verified = await getVerificationResult(instanceId);
    if (verified?.instance_id !== instanceId) {
      throw new Error('Verification result did not match this session.');
    }
    setResult(verified);
    setStatus(isApprovedVerificationResult(verified) ? 'completed' : 'failed');
    if (onComplete) onComplete(verified);
  };

  useEffect(() => {
    if (!instanceId) return;
    if (TERMINAL_STATUSES.includes(status)) return;

    pollRef.current = setInterval(async () => {
      try {
        const updated = await getVerificationFlowInstance(instanceId);
        const updatedStatus = normalizeSessionStatus(updated.status || updated.state);
        if (updatedStatus === 'expired') {
          setStatus('expired');
          clearInterval(pollRef.current);
        } else if (TERMINAL_STATUSES.includes(updatedStatus)) {
          clearInterval(pollRef.current);
          await loadTerminalResult();
        } else {
          setStatus(updatedStatus);
        }
      } catch (err) {
        setStatus('failed');
        setError(err.message || 'Could not load the verified result.');
        clearInterval(pollRef.current);
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(pollRef.current);
  }, [instanceId, status, onComplete]);

  useEffect(() => {
    let mounted = true;
    supportsDigitalCredentials(DEFAULT_DC_API_PROTOCOL).then((supported) => {
      if (mounted) setDcApiAvailable(supported);
    });
    return () => { mounted = false; };
  }, []);

  const statusCfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const requestUri = session?.request_uri;
  const qrValue = session?.qr_code_data || requestUri;
  const transport = createPresentationTransport({ requestUri });
  const dcApiRequestUrl = session?.dc_api_request_url || (instanceId ? `/v1/flows/instances/${encodeURIComponent(instanceId)}/request?transport=dc_api` : '');
  const dcApiSubmitUrl = session?.dc_api_submit_url || (instanceId ? `/v1/flows/instances/${encodeURIComponent(instanceId)}/submit/dc-api` : '');

  const handleOpenWallet = async () => {
    setWalletBusy(true);
    setError(null);
    try {
      if (dcApiAvailable && dcApiRequestUrl && dcApiSubmitUrl) {
        const completed = await runOpenId4VpDigitalCredentialFlow({
          requestUrl: dcApiRequestUrl,
          submitUrl: dcApiSubmitUrl,
        });
        if (TERMINAL_STATUSES.includes(normalizeSessionStatus(completed.status || completed.result))) {
          await loadTerminalResult();
        }
        return;
      }

      const opened = await openDeepLink(transport.openUri);
      if (!opened) {
        setError('Wallet did not open. Use the QR code or copy the link instead.');
      }
    } catch (err) {
      setError(formatDigitalCredentialError(err));
    } finally {
      setWalletBusy(false);
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
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Open the wallet on this device, or ask the wallet holder to scan the
            QR code with their identity wallet app to share the required credentials.
          </Typography>

          {requestUri && (
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

          {requestUri && (
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

      {(status === 'failed' || status === 'expired') && (
        <Alert severity="error">
          {error || result?.decision_reason || (status === 'expired'
            ? 'The verification session expired before the wallet responded.'
            : 'Verification failed. The wallet did not satisfy the policy requirements.')}
        </Alert>
      )}
    </Box>
  );
}

export default QRDisplayStep;
