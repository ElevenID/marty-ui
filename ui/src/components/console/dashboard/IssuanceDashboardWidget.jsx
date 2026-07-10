/**
 * Issuance Dashboard Widget
 * 
 * Displays real-time metrics for credential offers and OID4VCI issuance:
 * - Active offers count
 * - Total scans today
 * - Success rate
 * - Quick actions to manage offers
 */

import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import {
  Box,
  Card,
  CardContent,
  CardActions,
  Typography,
  Button,
  Grid,
  Chip,
  Skeleton,
  Divider,
  Stack,
  Tooltip,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import QrCodeIcon from '@mui/icons-material/QrCode';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import sseService, { EVENT_TYPES } from '../../../services/sseService';
import { loadIssuanceMetrics } from '../../../application/issuance';

const SHOULD_LOG_ISSUANCE_WIDGET_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function logIssuanceWidgetError(message, error) {
  if (SHOULD_LOG_ISSUANCE_WIDGET_DIAGNOSTICS) {
    console.error(message, error);
  }
}

/**
 * Mini stat display
 */
function MiniStat({ label, value, icon: Icon, color = 'primary' }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      {Icon && (
        <Box
          sx={{
            bgcolor: `${color}.light`,
            borderRadius: 1,
            p: 0.5,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Icon sx={{ color: `${color}.main`, fontSize: 20 }} />
        </Box>
      )}
      <Box>
        <Typography variant="h6" fontWeight="bold">
          {value}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {label}
        </Typography>
      </Box>
    </Box>
  );
}

MiniStat.propTypes = {
  label: PropTypes.string.isRequired,
  value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
  icon: PropTypes.elementType,
  color: PropTypes.string,
};

/**
 * Main Issuance Dashboard Widget
 */
export default function IssuanceDashboardWidget({ compact = false }) {
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId || authOrganizationId;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [metrics, setMetrics] = useState({
    activeOffers: 0,
    totalScans: 0,
    successRate: 0,
    totalOffers: 0,
  });

  /**
   * Fetch issuance metrics
   */
  const fetchMetrics = useCallback(async () => {
    if (!organizationId) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const { metrics: loaded, error: loadError } = await loadIssuanceMetrics({ organizationId });
      if (loadError) throw new Error(loadError);
      setMetrics(loaded);
    } catch (err) {
      logIssuanceWidgetError('Error fetching issuance metrics:', err);
      setError(t('dashboard.issuance.failedToLoad'));
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  // Fetch metrics on mount
  useEffect(() => {
    fetchMetrics();
  }, [fetchMetrics]);

  // Auto-refresh every 60 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      fetchMetrics();
    }, 60000);
    
    return () => clearInterval(interval);
  }, [fetchMetrics]);

  // Bump counters live when credential events arrive via SSE
  useEffect(() => {
    const unsub = sseService.on(EVENT_TYPES.CREDENTIAL_ISSUED, () => {
      setMetrics((prev) => ({
        ...prev,
        totalScans: prev.totalScans + 1,
        totalOffers: prev.totalOffers,
      }));
    });
    return unsub;
  }, []);

  if (loading && !metrics.activeOffers) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Skeleton variant="text" width={180} height={28} />
          <Skeleton variant="text" width={80} height={40} sx={{ mt: 1 }} />
          <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
            <Skeleton variant="rounded" width={100} height={24} />
            <Skeleton variant="rounded" width={60} height={24} />
          </Stack>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Typography color="error">{error}</Typography>
        </CardContent>
      </Card>
    );
  }

  if (compact) {
    // Compact view for dashboard grid
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Box>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                {t('dashboard.issuance.activeCredentialOffers')}
              </Typography>
              <Typography variant="h4" fontWeight="bold">
                {metrics.activeOffers}
              </Typography>
            </Box>
            <Box
              sx={{
                bgcolor: 'primary.light',
                borderRadius: 2,
                p: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <QrCodeIcon sx={{ color: 'primary.main', fontSize: 32 }} />
            </Box>
          </Box>
          
          <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
            <Tooltip title={t('dashboard.issuance.scansInLast24h')}>
              <Chip
                icon={<VisibilityIcon />}
                label={t('dashboard.issuance.scans', { count: metrics.totalScans })}
                size="small"
                variant="outlined"
              />
            </Tooltip>
            <Tooltip title={t('dashboard.issuance.successRateTooltip')}>
              <Chip
                icon={<CheckCircleIcon />}
                label={`${metrics.successRate}%`}
                size="small"
                color="success"
                variant="outlined"
              />
            </Tooltip>
          </Stack>
        </CardContent>
        <CardActions>
          <Button
            size="small"
            component={Link}
            to="/console/org/operate/issuance"
            endIcon={<ArrowForwardIcon />}
          >
            {t('dashboard.issuance.manageOffers')}
          </Button>
        </CardActions>
      </Card>
    );
  }

  // Full view for detailed display
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <QrCodeIcon />
          {t('dashboard.issuance.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {t('dashboard.issuance.description')}
        </Typography>
        
        <Divider sx={{ my: 2 }} />

        <Grid container spacing={3}>
          <Grid item xs={6} sm={3}>
            <MiniStat
              label={t('dashboard.issuance.activeOffers')}
              value={metrics.activeOffers}
              icon={QrCodeIcon}
              color="primary"
            />
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <MiniStat
              label={t('dashboard.issuance.totalOffers')}
              value={metrics.totalOffers}
              icon={TrendingUpIcon}
              color="info"
            />
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <MiniStat
              label={t('dashboard.issuance.totalScans')}
              value={metrics.totalScans}
              icon={VisibilityIcon}
              color="secondary"
            />
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <MiniStat
              label={t('dashboard.issuance.successRate')}
              value={`${metrics.successRate}%`}
              icon={CheckCircleIcon}
              color="success"
            />
          </Grid>
        </Grid>
      </CardContent>
      
      <Divider />
      
      <CardActions>
        <Button
          size="small"
          component={Link}
          to="/console/org/operate/issuance"
          endIcon={<ArrowForwardIcon />}
        >
          {t('dashboard.issuance.viewAllOffers')}
        </Button>
        <Button
          size="small"
          component={Link}
          to="/console/org/operate/issuance"
          state={{ tab: 2 }}
          endIcon={<ArrowForwardIcon />}
        >
          {t('dashboard.issuance.viewAnalytics')}
        </Button>
      </CardActions>
    </Card>
  );
}

IssuanceDashboardWidget.propTypes = {
  compact: PropTypes.bool,
};
