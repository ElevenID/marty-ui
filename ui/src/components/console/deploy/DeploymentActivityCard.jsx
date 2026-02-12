/**
 * Deployment Activity Card Component
 * 
 * Shows deployment profile with runtime activity metrics:
 * - Active/Inactive status
 * - Last issuance timestamp
 * - Last verification timestamp  
 * - QR enabled status
 * - Active flows count
 */

import { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Box,
  Chip,
  Button,
  Grid,
  Skeleton,
  Tooltip,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import BadgeIcon from '@mui/icons-material/Badge';
import { useTranslation } from 'react-i18next';

import { getDeploymentActivity } from '../../../services/deploymentProfilesApi';

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp, t) {
  if (!timestamp) return t('deploy.deploymentActivityCard.time.never');
  const date = new Date(timestamp);
  const now = new Date();
  const diff = now - date;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (minutes < 1) return t('deploy.deploymentActivityCard.time.justNow');
  if (minutes < 60) return t('deploy.deploymentActivityCard.time.minutesAgo', { count: minutes });
  if (hours < 24) return t('deploy.deploymentActivityCard.time.hoursAgo', { count: hours });
  if (days < 7) return t('deploy.deploymentActivityCard.time.daysAgo', { count: days });
  return date.toLocaleDateString();
}

/**
 * Deployment Activity Card Component
 */
export function DeploymentActivityCard({ deployment }) {
  const { t } = useTranslation('console');
  const [activity, setActivity] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchActivity() {
      if (!deployment?.id) return;
      
      try {
        const data = await getDeploymentActivity(deployment.id);
        setActivity(data);
      } catch (error) {
        console.error('Failed to load deployment activity:', error);
        // Set default empty activity
        setActivity({
          last_issuance: null,
          last_verification: null,
          active_flows: [],
          qr_enabled: false,
        });
      } finally {
        setLoading(false);
      }
    }

    fetchActivity();
  }, [deployment?.id]);

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Skeleton variant="text" width="60%" height={32} />
          <Skeleton variant="rectangular" height={80} sx={{ mt: 2 }} />
        </CardContent>
      </Card>
    );
  }

  const isActive = activity?.last_issuance || activity?.last_verification;
  const activeFlowCount = activity?.active_flows?.length || 0;

  return (
    <Card>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Typography variant="h6" fontWeight={600}>
            {deployment.name}
          </Typography>
          <Chip
            icon={isActive ? <CheckCircleIcon /> : <ErrorIcon />}
            label={isActive ? t('deploy.deploymentActivityCard.status.active') : t('deploy.deploymentActivityCard.status.inactive')}
            color={isActive ? 'success' : 'default'}
            size="small"
          />
        </Box>

        {deployment.description && (
          <Typography variant="body2" color="text.secondary" paragraph>
            {deployment.description}
          </Typography>
        )}

        {/* Activity Badges */}
        <Grid container spacing={1} sx={{ mb: 2 }}>
          <Grid item xs={12} sm={6}>
            <Tooltip title={t('deploy.deploymentActivityCard.tooltips.lastIssuance')}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BadgeIcon fontSize="small" color="primary" />
                <Typography variant="body2">
                  <strong>{t('deploy.deploymentActivityCard.labels.issued')}</strong> {formatTimestamp(activity?.last_issuance, t)}
                </Typography>
              </Box>
            </Tooltip>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Tooltip title={t('deploy.deploymentActivityCard.tooltips.lastVerification')}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <VerifiedUserIcon fontSize="small" color="primary" />
                <Typography variant="body2">
                  <strong>{t('deploy.deploymentActivityCard.labels.verified')}</strong> {formatTimestamp(activity?.last_verification, t)}
                </Typography>
              </Box>
            </Tooltip>
          </Grid>
        </Grid>

        {/* Status Chips */}
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {activity?.qr_enabled && (
            <Chip
              icon={<QrCode2Icon />}
              label={t('deploy.deploymentActivityCard.chips.qrEnabled')}
              size="small"
              color="primary"
              variant="outlined"
            />
          )}
          {activeFlowCount > 0 && (
            <Chip
              label={t('deploy.deploymentActivityCard.chips.activeFlows', { count: activeFlowCount })}
              size="small"
              color="success"
              variant="outlined"
            />
          )}
          {deployment.network_mode && (
            <Chip
              label={deployment.network_mode}
              size="small"
              variant="outlined"
            />
          )}
        </Box>
      </CardContent>

      <CardActions>
        <Button
          component={RouterLink}
          to={`/console/deploy/profiles/${deployment.id}`}
          size="small"
        >
          {t('deploy.deploymentActivityCard.actions.viewDetails')}
        </Button>
        <Button
          component={RouterLink}
          to={`/console/deploy/profiles/${deployment.id}/edit`}
          size="small"
        >
          {t('deploy.deploymentActivityCard.actions.edit')}
        </Button>
      </CardActions>
    </Card>
  );
}

export default DeploymentActivityCard;
