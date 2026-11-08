/**
 * Runtime Readiness Panel
 * 
 * Shows credential operation readiness reported by the gateway:
 * - Can issue credentials? (issuer configuration, deployment, issuance flow)
 * - Can verify credentials? (presentation policy, deployment)
 * - Is an issuer DID referenced by an active credential template?
 * - Last successful issuance timestamp
 * - Last successful verification timestamp
 * 
 * These readiness flags do not establish live signing-key validity.
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
import { Link as RouterLink } from 'react-router';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import BadgeIcon from '@mui/icons-material/Badge';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import DashboardErrorAlert from './DashboardErrorAlert';

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
    <Card component="section" aria-label={label} sx={{ height: '100%' }}>
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
            <Typography variant="caption" color="text.primary" sx={{ display: 'block', fontWeight: 600, mb: 0.5 }}>
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
export function RuntimeReadinessPanel({ runtimeStatus, error = null, onRetry }) {
  const { t } = useTranslation('console');

  const hasRuntimeStatus = runtimeStatus && [
    'canIssue', 'canVerify', 'issuerKeysValid', 'issuerActive', 'deploymentActive', 'policyReachable',
  ].every((field) => typeof runtimeStatus[field] === 'boolean');
  
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
  const issuanceStatus = canIssue && issuerKeysValid && issuerActive && deploymentActive ? 'ready' :
                         (issuerKeysValid || issuerActive) ? 'degraded' : 'error';
  
  const issuanceStatusText = issuanceStatus === 'ready' ? t('dashboard.runtimeReadiness.ready') :
                            issuanceStatus === 'degraded' ? t('dashboard.runtimeReadiness.degraded') : t('dashboard.runtimeReadiness.notReady');
  
  const issuerNeedsReview = !issuerKeysValid || !issuerActive;
  const issuanceDetails = issuerNeedsReview ? t('dashboard.runtimeReadiness.issuance.issuerConfigurationRequired') :
                         !deploymentActive ? t('dashboard.runtimeReadiness.issuance.noDeployments') :
                         !canIssue ? t('dashboard.runtimeReadiness.issuance.notReady') :
                         t('dashboard.runtimeReadiness.issuance.operational');

  const issuanceReason = issuerNeedsReview
    ? t('dashboard.runtimeReadiness.issuance.issuerConfigurationReason')
    : !deploymentActive
    ? t('dashboard.runtimeReadiness.issuance.deploymentsReason')
    : !canIssue
    ? t('dashboard.runtimeReadiness.issuance.readinessReason')
    : null;

  const issuanceAction = issuerNeedsReview
    ? { label: t('dashboard.runtimeReadiness.issuerConfiguration.manage'), link: '/console/org/deploy/issuer-identity' }
    : !deploymentActive
    ? { label: t('dashboard.runtimeReadiness.issuance.configureDeployment'), link: '/console/org/deploy/profiles' }
    : !canIssue
    ? { label: t('dashboard.runtimeReadiness.issuance.reviewFlows'), link: '/console/org/flows/definitions' }
    : null;

  // Compute verification status
  const verificationStatus = canVerify && deploymentActive && policyReachable ? 'ready' :
                            (deploymentActive || policyReachable) ? 'degraded' : 'error';
  
  const verificationStatusText = verificationStatus === 'ready' ? t('dashboard.runtimeReadiness.ready') :
                                verificationStatus === 'degraded' ? t('dashboard.runtimeReadiness.degraded') : t('dashboard.runtimeReadiness.notReady');
  
  const verificationDetails = !deploymentActive ? t('dashboard.runtimeReadiness.verification.noDeployments') :
                             !policyReachable ? t('dashboard.runtimeReadiness.verification.policyUnreachable') :
                             !canVerify ? t('dashboard.runtimeReadiness.verification.notReady') :
                             t('dashboard.runtimeReadiness.verification.operational');

  const verificationReason = !deploymentActive
    ? t('dashboard.runtimeReadiness.verification.deploymentsReason')
    : !policyReachable
    ? t('dashboard.runtimeReadiness.verification.policyReason')
    : !canVerify
    ? t('dashboard.runtimeReadiness.verification.readinessReason')
    : null;

  const verificationAction = !deploymentActive
    ? { label: t('dashboard.runtimeReadiness.verification.configureDeployment'), link: '/console/org/deploy/profiles' }
    : !policyReachable
    ? { label: t('dashboard.runtimeReadiness.verification.fixPolicies'), link: '/console/org/policies/presentation' }
    : !canVerify
    ? { label: t('dashboard.runtimeReadiness.verification.reviewSetup'), link: '/console/org/deploy/profiles' }
    : null;

  // The gateway's issuer flag describes an active template's DID reference;
  // it is not a live cryptographic health check of the signing key.
  const issuerConfigurationReason = !issuerActive
    ? t('dashboard.runtimeReadiness.issuerConfiguration.reason')
    : null;

  const issuerConfigurationAction = !issuerActive
    ? { label: t('dashboard.runtimeReadiness.issuerConfiguration.manage'), link: '/console/org/deploy/issuer-identity' }
    : null;

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        {t('dashboard.runtimeReadiness.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('dashboard.runtimeReadiness.description')}
      </Typography>

      {error || !hasRuntimeStatus ? (
        <DashboardErrorAlert
          title="Runtime readiness unavailable"
          error={error}
          onRetry={onRetry}
          fallback="Runtime readiness could not be loaded from a live backing source."
        />
      ) : (
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 4 }}>
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
        <Grid size={{ xs: 12, md: 4 }}>
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
        <Grid size={{ xs: 12, md: 4 }}>
          <StatusCard
            icon={VpnKeyIcon}
            label={t('dashboard.runtimeReadiness.issuerConfiguration.title')}
            status={issuerActive ? 'ready' : 'error'}
            statusText={t(issuerActive
              ? 'dashboard.runtimeReadiness.issuerConfiguration.configured'
              : 'dashboard.runtimeReadiness.issuerConfiguration.notConfigured')}
            details={t(issuerActive
              ? 'dashboard.runtimeReadiness.issuerConfiguration.configuredDetail'
              : 'dashboard.runtimeReadiness.issuerConfiguration.notConfiguredDetail')}
            reason={issuerConfigurationReason}
            actionLabel={issuerConfigurationAction?.label}
            actionLink={issuerConfigurationAction?.link}
          />
        </Grid>
      </Grid>
      )}
    </Paper>
  );
}
