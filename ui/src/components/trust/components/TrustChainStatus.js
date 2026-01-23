/**
 * Trust Chain Status Component
 * 
 * Displays the status of the PKI trust chain including:
 * - Root CA validity and expiry
 * - Intermediate CA validity and expiry
 * - CRL (Certificate Revocation List) status
 * - Overall health indicator
 * 
 * Extracted from TrustAnchor.js for reuse in onboarding and settings.
 */

import React from 'react';
import {
  Box,
  Typography,
  Alert,
  Chip,
  Divider,
  CircularProgress,
  Paper,
  Button,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import { HealthStatus } from '../ports/types';

/**
 * Get status icon and color based on status string.
 */
const getStatusDisplay = (status) => {
  switch (status) {
    case 'valid':
    case HealthStatus.VALID:
      return { icon: <CheckCircleIcon fontSize="small" />, color: 'success' };
    case 'expiring_soon':
    case HealthStatus.WARNING:
      return { icon: <WarningIcon fontSize="small" />, color: 'warning' };
    case 'expired':
    case 'invalid':
    case HealthStatus.ERROR:
      return { icon: <ErrorIcon fontSize="small" />, color: 'error' };
    default:
      return { icon: null, color: 'default' };
  }
};

/**
 * Single chain item row.
 */
const ChainItem = ({ label, status, expires, subject }) => {
  const { icon, color } = getStatusDisplay(status);
  const statusLabel = status === 'valid' ? 'Valid' : 
                     status === 'expiring_soon' ? 'Expiring Soon' :
                     status === 'expired' ? 'Expired' : 
                     status === 'invalid' ? 'Invalid' : status;

  return (
    <Box sx={{ mb: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="body2" fontWeight="medium">
          {label}
        </Typography>
        <Chip
          icon={icon}
          label={statusLabel}
          color={color}
          size="small"
          variant="outlined"
        />
      </Box>
      {expires && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
          Expires: {expires}
        </Typography>
      )}
      {subject && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
          {subject}
        </Typography>
      )}
    </Box>
  );
};

/**
 * CRL Status row.
 */
const CrlStatusItem = ({ status }) => {
  const statusMap = {
    'up_to_date': { label: 'Up to date', color: 'success' },
    'stale': { label: 'Stale', color: 'warning' },
    'unavailable': { label: 'Unavailable', color: 'error' },
  };

  const { label, color } = statusMap[status] || { label: status, color: 'default' };

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
      <Typography variant="body2" fontWeight="medium">
        CRL Status
      </Typography>
      <Chip
        label={label}
        color={color}
        size="small"
        variant="outlined"
      />
    </Box>
  );
};

/**
 * Trust Chain Status Component.
 * 
 * @param {Object} props
 * @param {import('../ports/types').TrustChainStatus} props.chainStatus - Chain status data
 * @param {boolean} [props.loading] - Loading state
 * @param {function} [props.onRefresh] - Refresh callback
 * @param {boolean} [props.showTitle] - Show title header
 * @param {boolean} [props.compact] - Compact mode (no paper wrapper)
 */
const TrustChainStatus = ({
  chainStatus,
  loading = false,
  onRefresh,
  showTitle = true,
  compact = false,
}) => {
  const content = (
    <>
      {showTitle && (
        <>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
            <Typography variant="h6">
              Trust Chain Status
            </Typography>
            {onRefresh && (
              <Button
                size="small"
                startIcon={loading ? <CircularProgress size={16} /> : <RefreshIcon />}
                onClick={onRefresh}
                disabled={loading}
              >
                Refresh
              </Button>
            )}
          </Box>
          <Divider sx={{ mb: 2 }} />
        </>
      )}

      {loading && !chainStatus && (
        <Box display="flex" justifyContent="center" p={2}>
          <CircularProgress size={24} />
        </Box>
      )}

      {chainStatus && (
        <>
          {chainStatus.rootCA && (
            <ChainItem
              label="Root CA"
              status={chainStatus.rootCA.status}
              expires={chainStatus.rootCA.expires}
              subject={chainStatus.rootCA.subject}
            />
          )}

          {chainStatus.intermediateCA && (
            <ChainItem
              label="Intermediate CA"
              status={chainStatus.intermediateCA.status}
              expires={chainStatus.intermediateCA.expires}
              subject={chainStatus.intermediateCA.subject}
            />
          )}

          {chainStatus.crlStatus && (
            <CrlStatusItem status={chainStatus.crlStatus} />
          )}

          <Alert
            severity={chainStatus.healthy ? 'success' : 'warning'}
            sx={{ mt: 2 }}
            icon={chainStatus.healthy ? <CheckCircleIcon /> : <WarningIcon />}
          >
            {chainStatus.healthy
              ? 'Trust chain is healthy and operational.'
              : 'Trust chain has issues that need attention.'}
          </Alert>
        </>
      )}

      {!loading && !chainStatus && (
        <Alert severity="info">
          No trust chain configured. Complete trust profile setup to view chain status.
        </Alert>
      )}
    </>
  );

  if (compact) {
    return content;
  }

  return (
    <Paper sx={{ p: 3, bgcolor: 'grey.50' }}>
      {content}
    </Paper>
  );
};

export default TrustChainStatus;
