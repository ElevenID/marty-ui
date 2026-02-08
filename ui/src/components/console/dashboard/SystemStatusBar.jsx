/**
 * System Status Bar
 * 
 * Displays real-time health status for:
 * - API Gateway
 * - Issuer Metadata Service
 * - Verifier Service
 * 
 * Shows prominent banner if any service is in error state.
 */

import {
  Box,
  Paper,
  Typography,
  Grid,
  Alert,
  IconButton,
  Tooltip,
} from '@mui/material';
import { Link } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { HealthStatus } from '../../../services/healthApi';

/**
 * Status indicator for a single service
 */
function ServiceStatusIndicator({ status, label, onClick }) {
  const getStatusIcon = () => {
    switch (status) {
      case HealthStatus.HEALTHY:
        return <CheckCircleIcon color="success" />;
      case HealthStatus.WARNING:
        return <WarningIcon color="warning" />;
      case HealthStatus.ERROR:
        return <ErrorIcon color="error" />;
      case HealthStatus.UNKNOWN:
      default:
        return <HelpOutlineIcon color="disabled" />;
    }
  };

  const getStatusText = () => {
    switch (status) {
      case HealthStatus.HEALTHY:
        return 'Healthy';
      case HealthStatus.WARNING:
        return 'Degraded';
      case HealthStatus.ERROR:
        return 'Error';
      case HealthStatus.UNKNOWN:
      default:
        return 'Unknown';
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case HealthStatus.HEALTHY:
        return 'success.main';
      case HealthStatus.WARNING:
        return 'warning.main';
      case HealthStatus.ERROR:
        return 'error.main';
      case HealthStatus.UNKNOWN:
      default:
        return 'text.disabled';
    }
  };

  return (
    <Tooltip title="Click to view audit logs" placement="top">
      <Box
        onClick={onClick}
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          cursor: 'pointer',
          '&:hover': {
            opacity: 0.8,
          },
        }}
      >
        {getStatusIcon()}
        <Box>
          <Typography variant="body2" fontWeight={500}>
            {label}
          </Typography>
          <Typography
            variant="caption"
            sx={{ color: getStatusColor() }}
          >
            {getStatusText()}
          </Typography>
        </Box>
      </Box>
    </Tooltip>
  );
}

/**
 * System Status Bar Component
 */
export function SystemStatusBar({ systemHealth }) {
  if (!systemHealth) {
    return null;
  }

  const { gateway, issuer, verifier } = systemHealth;
  const hasError = [gateway, issuer, verifier].includes(HealthStatus.ERROR);
  const hasWarning = [gateway, issuer, verifier].includes(HealthStatus.WARNING);

  const handleServiceClick = (serviceName) => {
    // Navigate to audit logs filtered by service
    window.location.href = `/console/audit?service=${serviceName}`;
  };

  return (
    <Box sx={{ mb: 3 }}>
      {/* Error Banner */}
      {hasError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          One or more services are experiencing issues. Click on a service below to view logs.
        </Alert>
      )}

      {/* Warning Banner */}
      {!hasError && hasWarning && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          One or more services are degraded. System may experience reduced performance.
        </Alert>
      )}

      {/* Status Bar */}
      <Paper sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5 }}>
          <Typography variant="h6">
            System Status
          </Typography>
          <IconButton
            size="small"
            component={Link}
            to="/console/audit"
            title="View all audit logs"
          >
            <OpenInNewIcon fontSize="small" />
          </IconButton>
        </Box>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={4}>
            <ServiceStatusIndicator
              status={gateway}
              label="API Gateway"
              onClick={() => handleServiceClick('gateway')}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <ServiceStatusIndicator
              status={issuer}
              label="Issuer Metadata"
              onClick={() => handleServiceClick('issuer')}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <ServiceStatusIndicator
              status={verifier}
              label="Verifier Service"
              onClick={() => handleServiceClick('verifier')}
            />
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
}
