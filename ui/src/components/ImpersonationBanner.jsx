import { useState, useEffect } from 'react';
import {
  Alert,
  AlertTitle,
  Button,
  Box,
  Typography,
  Snackbar,
} from '@mui/material';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import VisibilityIcon from '@mui/icons-material/Visibility';
import {
  getImpersonationStatus,
  stopImpersonation,
} from '../services/adminImpersonationApi';

/**
 * Impersonation Banner
 * 
 * Displays a prominent banner when a platform admin is impersonating an organization.
 * Shows read-only indicator and provides a button to stop impersonation.
 */
export default function ImpersonationBanner() {
  const [status, setStatus] = useState({ is_impersonating: false });
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Only check status for authenticated users
    let mounted = true;
    
    const checkStatus = async () => {
      try {
        const impersonationStatus = await getImpersonationStatus();
        if (mounted) {
          setStatus(impersonationStatus);
        }
      } catch (err) {
        // Silently fail - not impersonating or API not available
        console.debug('Impersonation status check failed (expected if not admin):', err.message);
        if (mounted) {
          setStatus({ is_impersonating: false });
        }
      }
    };
    
    checkStatus();
    // Poll status every 30 seconds
    const interval = setInterval(checkStatus, 30000);
    
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleStopImpersonation = async () => {
    try {
      setStopping(true);
      setError(null);
      await stopImpersonation();
      
      // Refresh the page to clear impersonated state
      window.location.reload();
    } catch (err) {
      console.error('Failed to stop impersonation:', err);
      setError(err.message || 'Failed to stop impersonation');
    } finally {
      setStopping(false);
    }
  };

  // Don't render anything if not impersonating
  if (!status || !status.is_impersonating) {
    return null;
  }

  return (
    <>
      <Alert
        severity="warning"
        icon={<AdminPanelSettingsIcon />}
        sx={{
          position: 'sticky',
          top: 0,
          zIndex: 1200,
          borderRadius: 0,
          borderBottom: '2px solid',
          borderColor: 'warning.main',
        }}
        action={
          <Button
            color="inherit"
            size="small"
            onClick={handleStopImpersonation}
            disabled={stopping}
          >
            {stopping ? 'Stopping...' : 'Stop Impersonation'}
          </Button>
        }
      >
        <AlertTitle sx={{ fontWeight: 'bold' }}>
          Platform Admin - Impersonation Active
        </AlertTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="body2">
            You are currently impersonating:{' '}
            <strong>{status.impersonated_org_name}</strong>
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <VisibilityIcon fontSize="small" />
            <Typography variant="body2" fontWeight="medium">
              Read-Only Mode
            </Typography>
          </Box>
          {status.impersonation_started_at && (
            <Typography variant="caption" color="text.secondary">
              Started: {new Date(status.impersonation_started_at).toLocaleString()}
            </Typography>
          )}
        </Box>
      </Alert>

      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Snackbar>
    </>
  );
}
