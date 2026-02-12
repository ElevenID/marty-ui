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
import { useTranslation } from 'react-i18next';

import { HealthStatus } from '../../../services/healthApi';

/**
 * Status indicator for a single service
 */
function ServiceStatusIndicator({ status, label, onClick }) {
  const { t } = useTranslation('console');
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
        return t('dashboard.systemStatus.healthy');
      case HealthStatus.WARNING:
        return t('dashboard.systemStatus.degraded');
      case HealthStatus.ERROR:
        return t('dashboard.systemStatus.error');
      case HealthStatus.UNKNOWN:
      default:
        return t('dashboard.systemStatus.unknown');
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
    <Tooltip title={t('dashboard.systemStatus.clickToViewLogs')} placement="top">
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
  const { t } = useTranslation('console');
  
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
          {t('dashboard.systemStatus.errorBanner')}
        </Alert>
      )}

      {/* Warning Banner */}
      {!hasError && hasWarning && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t('dashboard.systemStatus.warningBanner')}
        </Alert>
      )}

      {/* Status Bar */}
      <Paper sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5 }}>
          <Typography variant="h6">
            {t('dashboard.systemStatus.title')}
          </Typography>
          <IconButton
            size="small"
            component={Link}
            to="/console/audit"
            title={t('dashboard.systemStatus.viewAllLogs')}
          >
            <OpenInNewIcon fontSize="small" />
          </IconButton>
        </Box>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={4}>
            <ServiceStatusIndicator
              status={gateway}
              label={t('dashboard.systemStatus.apiGateway')}
              onClick={() => handleServiceClick('gateway')}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <ServiceStatusIndicator
              status={issuer}
              label={t('dashboard.systemStatus.issuerMetadata')}
              onClick={() => handleServiceClick('issuer')}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <ServiceStatusIndicator
              status={verifier}
              label={t('dashboard.systemStatus.verifierService')}
              onClick={() => handleServiceClick('verifier')}
            />
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
}
