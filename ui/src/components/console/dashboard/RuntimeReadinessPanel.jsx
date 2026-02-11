/**
 * Runtime Readiness Panel
 * 
 * Shows runtime operational status (not just configuration):
 * - Can issue credentials? (keys valid, issuer active)
 * - Can verify credentials? (policy reachable, deployment active)
 * - Last successful issuance timestamp
 * - Last successful verification timestamp
 * 
 * Purpose: answers "Is it actually working?" vs "Is it configured?"
 */

import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import BadgeIcon from '@mui/icons-material/Badge';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

/**
 * Format relative time for last activity
 */
function formatLastActivity(timestamp) {
  if (!timestamp) return 'Never';
  
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now - date;
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMinutes < 1) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

/**
 * Status indicator card with actionable fixes
 */
function StatusCard({ 
  icon: Icon, 
  label, 
  status, 
  statusText, 
  lastActivity, 
  details, 
  reason, 
  actionLabel, 
  actionLink 
}) {
  const getStatusColor = () => {
    switch (status) {
      case 'ready':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'error':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case 'ready':
        return <CheckCircleIcon />;
      case 'degraded':
        return <WarningIcon />;
      case 'error':
        return <ErrorIcon />;
      default:
        return <ErrorIcon />;
    }
  };

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <Icon color={getStatusColor()} />
          <Typography variant="subtitle2" fontWeight={600}>
            {label}
          </Typography>
        </Box>

        <Chip
          icon={getStatusIcon()}
          label={statusText}
          color={getStatusColor()}
          size="small"
          sx={{ mb: 2 }}
        />

        {lastActivity && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 1 }}>
            <AccessTimeIcon fontSize="small" color="action" />
            <Typography variant="caption" color="text.secondary">
              Last: {formatLastActivity(lastActivity)}
            </Typography>
          </Box>
        )}

        {details && (
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            {details}
          </Typography>
        )}

        {/* Why explanation - shown when not ready */}
        {reason && status !== 'ready' && (
          <Box sx={{ mt: 2, p: 1.5, bgcolor: 'background.default', borderRadius: 1 }}>
            <Typography variant="caption" fontWeight={600} color="text.primary" display="block" gutterBottom>
              Why this matters:
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {reason}
            </Typography>
          </Box>
        )}

        {/* Fix action button */}
        {actionLabel && actionLink && status !== 'ready' && (
          <Box sx={{ mt: 2 }}>
            <Button
              component={RouterLink}
              to={actionLink}
              variant="outlined"
              size="small"
              endIcon={<ArrowForwardIcon />}
              fullWidth
              color={status === 'error' ? 'error' : 'warning'}
            >
              {actionLabel}
            </Button>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Runtime Readiness Panel Component
 */
export function RuntimeReadinessPanel({ runtimeStatus }) {
  // Extract runtime status data
  const {
    canIssue = false,
    canVerify = false,
    issuerKeysValid = false,
    issuerActive = false,
    deploymentActive = false,
    policyReachable = false,
    lastIssuance = null,
    lastVerification = null,
  } = runtimeStatus || {};

  // Compute issuance status
  const issuanceStatus = canIssue && issuerKeysValid && issuerActive ? 'ready' : 
                         (issuerKeysValid || issuerActive) ? 'degraded' : 'error';
  
  const issuanceStatusText = canIssue ? 'Ready' : 
                            (issuerKeysValid || issuerActive) ? 'Degraded' : 'Not Ready';
  
  const issuanceDetails = !issuerKeysValid ? 'Keys invalid or expired' :
                         !issuerActive ? 'Issuer not active' :
                         'All systems operational';

  const issuanceReason = !issuerKeysValid 
    ? 'Valid signing keys are required to sign and issue verifiable credentials. Without them, credential issuance cannot proceed.'
    : !issuerActive
    ? 'The issuer service must be active and properly configured to handle credential issuance requests.'
    : null;

  const issuanceAction = !issuerKeysValid 
    ? { label: 'Fix Signing Keys', link: '/console/deploy/signing-keys' }
    : !issuerActive
    ? { label: 'Activate Issuer', link: '/console/org/settings' }
    : null;

  // Compute verification status
  const verificationStatus = canVerify && deploymentActive && policyReachable ? 'ready' :
                            (deploymentActive || policyReachable) ? 'degraded' : 'error';
  
  const verificationStatusText = canVerify ? 'Ready' : 
                                (deploymentActive || policyReachable) ? 'Degraded' : 'Not Ready';
  
  const verificationDetails = !deploymentActive ? 'No active deployments' :
                             !policyReachable ? 'Policy unreachable' :
                             'All systems operational';

  const verificationReason = !deploymentActive
    ? 'At least one deployment profile must be active to verify credentials. Deployments define the trust policies and verification rules.'
    : !policyReachable
    ? 'Presentation policies must be accessible to validate credentials during verification.'
    : null;

  const verificationAction = !deploymentActive
    ? { label: 'Configure Deployment', link: '/console/deploy/profiles' }
    : !policyReachable
    ? { label: 'Fix Policies', link: '/console/policies/presentation' }
    : null;

  const signingKeysReason = !issuerKeysValid
    ? 'Signing keys authenticate your organization as a credential issuer. expired or invalid keys prevent credential issuance and may invalidate issued credentials.'
    : null;

  const signingKeysAction = !issuerKeysValid
    ? { label: 'Manage Keys', link: '/console/deploy/signing-keys' }
    : null;

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        Runtime Operational Status
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Real-time readiness for credential operations
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <StatusCard
            icon={BadgeIcon}
            label="Credential Issuance"
            status={issuanceStatus}
            statusText={issuanceStatusText}
            lastActivity={lastIssuance}
            details={issuanceDetails}
            reason={issuanceReason}
            actionLabel={issuanceAction?.label}
            actionLink={issuanceAction?.link}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <StatusCard
            icon={VerifiedUserIcon}
            label="Credential Verification"
            status={verificationStatus}
            statusText={verificationStatusText}
            lastActivity={lastVerification}
            details={verificationDetails}
            reason={verificationReason}
            actionLabel={verificationAction?.label}
            actionLink={verificationAction?.link}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <StatusCard
            icon={VpnKeyIcon}
            label="Signing Keys"
            status={issuerKeysValid ? 'ready' : 'error'}
            statusText={issuerKeysValid ? 'Valid' : 'Invalid'}
            details={issuerKeysValid ? 'Keys are valid and active' : 'Keys require attention'}
            reason={signingKeysReason}
            actionLabel={signingKeysAction?.label}
            actionLink={signingKeysAction?.link}
          />
        </Grid>
      </Grid>
    </Paper>
  );
}
