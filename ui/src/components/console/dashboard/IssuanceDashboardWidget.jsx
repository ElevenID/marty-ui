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
  CircularProgress,
  Divider,
  Stack,
  Tooltip,
} from '@mui/material';
import { Link } from 'react-router-dom';
import QrCodeIcon from '@mui/icons-material/QrCode';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { useAuth } from '../../../hooks/useAuth';

const API_URL = import.meta.env.VITE_API_URL || '';

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
  const { organizationId } = useAuth();
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
      // Fetch analytics summary for last 1 day
      const analyticsParams = new URLSearchParams({
        organization_id: organizationId,
        days: '1',
      });
      
      const analyticsResponse = await fetch(
        `${API_URL}/api/issuance/analytics/summary?${analyticsParams.toString()}`,
        {
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
      
      if (analyticsResponse.ok) {
        const analyticsData = await analyticsResponse.json();
        setMetrics({
          activeOffers: analyticsData.active_offers || 0,
          totalScans: analyticsData.total_scans || 0,
          successRate: analyticsData.success_rate || 0,
          totalOffers: analyticsData.total_offers || 0,
        });
      }
    } catch (err) {
      console.error('Error fetching issuance metrics:', err);
      setError('Failed to load metrics');
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

  if (loading && !metrics.activeOffers) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', py: 4 }}>
            <CircularProgress size={40} />
          </Box>
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
                Active Credential Offers
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
            <Tooltip title="Scans in last 24 hours">
              <Chip
                icon={<VisibilityIcon />}
                label={`${metrics.totalScans} scans`}
                size="small"
                variant="outlined"
              />
            </Tooltip>
            <Tooltip title="Success rate">
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
            to="/console/operate/issuance"
            endIcon={<ArrowForwardIcon />}
          >
            Manage Offers
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
          Credential Issuance
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Real-time metrics for OID4VCI credential offers (Last 24 hours)
        </Typography>
        
        <Divider sx={{ my: 2 }} />

        <Grid container spacing={3}>
          <Grid item xs={6} sm={3}>
            <MiniStat
              label="Active Offers"
              value={metrics.activeOffers}
              icon={QrCodeIcon}
              color="primary"
            />
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <MiniStat
              label="Total Offers"
              value={metrics.totalOffers}
              icon={TrendingUpIcon}
              color="info"
            />
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <MiniStat
              label="Total Scans"
              value={metrics.totalScans}
              icon={VisibilityIcon}
              color="secondary"
            />
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <MiniStat
              label="Success Rate"
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
          to="/console/operate/issuance"
          endIcon={<ArrowForwardIcon />}
        >
          View All Offers
        </Button>
        <Button
          size="small"
          component={Link}
          to="/console/operate/issuance"
          state={{ tab: 2 }}
          endIcon={<ArrowForwardIcon />}
        >
          View Analytics
        </Button>
      </CardActions>
    </Card>
  );
}

IssuanceDashboardWidget.propTypes = {
  compact: PropTypes.bool,
};
