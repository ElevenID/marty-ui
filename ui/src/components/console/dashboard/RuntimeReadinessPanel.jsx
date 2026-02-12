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
import { useTranslation } from 'react-i18next';
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
function formatLastActivity(timestamp, t) {
  if (!timestamp) return t('dashboard.runtimeReadiness.never');
  
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now - date;
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMinutes < 1) return t('dashboard.runtimeReadiness.justNow');
  if (diffMinutes < 60) return t('dashboard.runtimeReadiness.minutesAgo', { minutes: diffMinutes });
  if (diffHours < 24) return t('dashboard.runtimeReadiness.hoursAgo', { hours: diffHours });
  if (diffDays < 7) return t('dashboard.runtimeReadiness.daysAgo', { days: diffDays });
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
  const { t } = useTranslation('console');
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
              {t('dashboard.runtimeReadiness.lastActivity', { time: formatLastActivity(lastActivity, t) })}
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
              {t('dashboard.runtimeReadiness.whyThisMatters')}
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
  const { t } = useTranslation('console');
  
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
  
  const issuanceStatusText = canIssue ? t('dashboard.runtimeReadiness.ready') : 
                            (issuerKeysValid || issuerActive) ? t('dashboard.runtimeReadiness.degraded') : t('dashboard.runtimeReadiness.notReady');
  
  const issuanceDetails = !issuerKeysValid ? t('dashboard.runtimeReadiness.issuance.keysInvalid') :
                         !issuerActive ? t('dashboard.runtimeReadiness.issuance.issuerInactive') :
                         t('dashboard.runtimeReadiness.issuance.operational');

  const issuanceReason = !issuerKeysValid 
    ? t('dashboard.runtimeReadiness.issuance.keysReason')
    : !issuerActive
    ? t('dashboard.runtimeReadiness.issuance.issuerReason')
    : null;

  const issuanceAction = !issuerKeysValid 
    ? { label: t('dashboard.runtimeReadiness.issuance.fixSigningKeys'), link: '/console/deploy/signing-keys' }
    : !issuerActive
    ? { label: t('dashboard.runtimeReadiness.issuance.activateIssuer'), link: '/console/org/settings' }
    : null;

  // Compute verification status
  const verificationStatus = canVerify && deploymentActive && policyReachable ? 'ready' :
                            (deploymentActive || policyReachable) ? 'degraded' : 'error';
  
  const verificationStatusText = canVerify ? t('dashboard.runtimeReadiness.ready') : 
                                (deploymentActive || policyReachable) ? t('dashboard.runtimeReadiness.degraded') : t('dashboard.runtimeReadiness.notReady');
  
  const verificationDetails = !deploymentActive ? t('dashboard.runtimeReadiness.verification.noDeployments') :
                             !policyReachable ? t('dashboard.runtimeReadiness.verification.policyUnreachable') :
                             t('dashboard.runtimeReadiness.verification.operational');

  const verificationReason = !deploymentActive
    ? t('dashboard.runtimeReadiness.verification.deploymentsReason')
    : !policyReachable
    ? t('dashboard.runtimeReadiness.verification.policyReason')
    : null;

  const verificationAction = !deploymentActive
    ? { label: t('dashboard.runtimeReadiness.verification.configureDeployment'), link: '/console/deploy/profiles' }
    : !policyReachable
    ? { label: t('dashboard.runtimeReadiness.verification.fixPolicies'), link: '/console/policies/presentation' }
    : null;

  const signingKeysReason = !issuerKeysValid
    ? t('dashboard.runtimeReadiness.keys.reason')
    : null;

  const signingKeysAction = !issuerKeysValid
    ? { label: t('dashboard.runtimeReadiness.keys.manageKeys'), link: '/console/deploy/signing-keys' }
    : null;

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        {t('dashboard.runtimeReadiness.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('dashboard.runtimeReadiness.description')}
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <StatusCard
            icon={BadgeIcon}
            label={t('dashboard.runtimeReadiness.credentialIssuance')}
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
            label={t('dashboard.runtimeReadiness.credentialVerification')}
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
            label={t('dashboard.runtimeReadiness.signingKeys')}
            status={issuerKeysValid ? 'ready' : 'error'}
            statusText={issuerKeysValid ? t('dashboard.runtimeReadiness.valid') : t('dashboard.runtimeReadiness.invalid')}
            details={issuerKeysValid ? t('dashboard.runtimeReadiness.keys.valid') : t('dashboard.runtimeReadiness.keys.needsAttention')}
            reason={signingKeysReason}
            actionLabel={signingKeysAction?.label}
            actionLink={signingKeysAction?.link}
          />
        </Grid>
      </Grid>
    </Paper>
  );
}
