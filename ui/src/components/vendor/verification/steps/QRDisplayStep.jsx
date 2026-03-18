import { useState, useEffect, useRef } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Alert,
  Chip,
  Divider,
  Paper,
} from '@mui/material';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassTopIcon from '@mui/icons-material/HourglassTop';
import { getVerificationSession } from '../../../../services/verificationApi';

const POLL_INTERVAL_MS = 3000;
const TERMINAL_STATUSES = ['completed', 'failed', 'expired'];

const STATUS_CONFIG = {
  pending: { label: 'Waiting for wallet', color: 'warning', icon: <HourglassTopIcon fontSize="small" /> },
  completed: { label: 'Verified', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
  failed: { label: 'Failed', color: 'error', icon: <ErrorIcon fontSize="small" /> },
  expired: { label: 'Expired', color: 'default', icon: <ErrorIcon fontSize="small" /> },
};

function QRDisplayStep({ session, onComplete }) {
  const [status, setStatus] = useState(session?.status || 'pending');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (!session?.session_id) return;
    if (TERMINAL_STATUSES.includes(status)) return;

    pollRef.current = setInterval(async () => {
      try {
        const updated = await getVerificationSession(session.session_id);
        setStatus(updated.status);
        if (TERMINAL_STATUSES.includes(updated.status)) {
          clearInterval(pollRef.current);
          setResult(updated);
          if (onComplete) onComplete(updated);
        }
      } catch (err) {
        setError(err.message || 'Failed to check session status');
        clearInterval(pollRef.current);
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(pollRef.current);
  }, [session?.session_id, status, onComplete]);

  const statusCfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const qrData = session?.qr_code_data;
  const requestUri = session?.request_uri;

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <QrCode2Icon color="primary" />
        <Typography variant="h6">Scan to Verify</Typography>
        <Chip
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
            Ask the wallet holder to scan the QR code with their identity wallet
            app to share the required credentials.
          </Typography>

          {qrData ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  display: 'inline-block',
                  background: '#fff',
                }}
              >
                <img
                  src={`data:image/png;base64,${qrData}`}
                  alt="OID4VP QR Code"
                  style={{ width: 220, height: 220, display: 'block' }}
                />
              </Paper>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress size={24} sx={{ mr: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Generating QR code…
              </Typography>
            </Box>
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
        <Alert severity="success" icon={<CheckCircleIcon />}>
          Verification successful.
          {result.verified_claims && Object.keys(result.verified_claims).length > 0 && (
            <Box component="ul" sx={{ mt: 1, mb: 0, pl: 2 }}>
              {Object.entries(result.verified_claims).map(([k, v]) => (
                <li key={k}>
                  <Typography variant="caption">
                    <strong>{k}:</strong> {String(v)}
                  </Typography>
                </li>
              ))}
            </Box>
          )}
        </Alert>
      )}

      {(status === 'failed' || status === 'expired') && (
        <Alert severity="error">
          {status === 'expired'
            ? 'The verification session expired before the wallet responded.'
            : 'Verification failed. The wallet did not satisfy the policy requirements.'}
        </Alert>
      )}
    </Box>
  );
}

export default QRDisplayStep;
