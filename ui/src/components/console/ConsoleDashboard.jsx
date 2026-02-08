/**
 * Console Dashboard
 * 
 * Main dashboard for Admin/Vendor users.
 * Shows status, alerts, and next step guidance.
 */

import { useMemo } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CardActions,
  Button,
  LinearProgress,
  Tooltip,
} from '@mui/material';
import { Link } from 'react-router-dom';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { useAuth } from '../../hooks/useAuth';
import { useDashboardData } from '../../hooks/useDashboardData';
import { DASHBOARD_QUICK_ACTIONS } from '../../config/navigation';
import { computeSetupReadiness, computeBlockers, computeQuickActionVisibility } from '../../config/dashboardRules';
import { SystemStatusBar } from './dashboard/SystemStatusBar';
import { SetupReadinessPanel } from './dashboard/SetupReadinessPanel';
import { BlockingIssuesPanel } from './dashboard/BlockingIssuesPanel';
import { RecentActivityPanel } from './dashboard/RecentActivityPanel';


/**
 * Quick action card with context-aware state
 */
function QuickActionCard({ action, disabled, tooltip }) {
  const Icon = action.icon;
  
  const cardContent = (
    <Card sx={{ 
      height: '100%',
      opacity: disabled ? 0.6 : 1,
      cursor: disabled ? 'not-allowed' : 'pointer',
    }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <Icon color={disabled ? 'disabled' : 'primary'} />
          <Typography variant="subtitle1" fontWeight={500}>
            {action.label}
          </Typography>
        </Box>
      </CardContent>
      <CardActions>
        <Button
          size="small"
          component={disabled ? 'button' : Link}
          to={disabled ? undefined : action.path}
          endIcon={<ArrowForwardIcon />}
          disabled={disabled}
        >
          Get Started
        </Button>
      </CardActions>
    </Card>
  );

  if (disabled && tooltip) {
    return (
      <Tooltip title={tooltip} placement="top">
        <Box sx={{ height: '100%' }}>
          {cardContent}
        </Box>
      </Tooltip>
    );
  }

  return cardContent;
}

function ConsoleDashboard() {
  const { user, organizationName } = useAuth();
  const { data, loading, error } = useDashboardData();

  // Compute setup readiness and blockers
  const readiness = useMemo(() => computeSetupReadiness(data), [data]);
  const blockers = useMemo(() => computeBlockers(readiness), [readiness]);
  const quickActionVisibility = useMemo(() => computeQuickActionVisibility(readiness), [readiness]);

  // Filter visible quick actions
  const visibleQuickActions = useMemo(() => {
    return DASHBOARD_QUICK_ACTIONS.adminVendor.filter(
      (action) => quickActionVisibility[action.id]?.visible !== false
    );
  }, [quickActionVisibility]);

  if (loading) {
    return (
      <Box sx={{ py: 4 }}>
        <LinearProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ py: 4 }}>
        <Typography color="error">Error loading dashboard: {error}</Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Dashboard
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Welcome back{user?.name ? `, ${user.name}` : ''}
          {organizationName && ` • ${organizationName}`}
        </Typography>
      </Box>

      {/* System Status Bar */}
      <SystemStatusBar systemHealth={data.systemHealth} />

      {/* Blocking Issues */}
      <BlockingIssuesPanel blockers={blockers} />

      {/* Setup Readiness */}
      <SetupReadinessPanel readiness={readiness} loading={loading} />

      {/* Next Step - Only show if there's a next valid action */}
      {visibleQuickActions.length > 0 && (
        <>
          <Typography variant="h6" gutterBottom>
            Next Step
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {visibleQuickActions.map((action) => {
              const actionVisibility = quickActionVisibility[action.id] || {};
              return (
                <Grid item xs={12} sm={6} md={4} lg={2.4} key={action.id}>
                  <QuickActionCard
                    action={action}
                    disabled={actionVisibility.disabled}
                    tooltip={actionVisibility.tooltip}
                  />
                </Grid>
              );
            })}
          </Grid>
        </>
      )}

      {/* Setup Complete Message - Show when all steps are Ready */}
      {visibleQuickActions.length === 0 && readiness.flow?.state === 'READY' && (
        <Paper sx={{ p: 3, mb: 4, bgcolor: 'success.light', color: 'success.contrastText' }}>
          <Typography variant="h6" gutterBottom>
            🎉 Setup Complete!
          </Typography>
          <Typography variant="body2" paragraph>
            All configuration steps are complete. You're ready to start processing credentials and applications.
          </Typography>
          <Button
            variant="contained"
            component={Link}
            to="/console/operate"
            endIcon={<ArrowForwardIcon />}
            sx={{ bgcolor: 'success.dark', '&:hover': { bgcolor: 'success.darker' } }}
          >
            Go to Operate
          </Button>
        </Paper>
      )}

      {/* Recent Activity */}
      <RecentActivityPanel />

      {/* Developer Resources */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Developer Resources
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Access API documentation, SDKs, and integration guides.
        </Typography>
        <Button
          variant="outlined"
          component={Link}
          to="/docs"
          endIcon={<OpenInNewIcon />}
        >
          View API Docs
        </Button>
      </Paper>
    </Box>
  );
}

export default ConsoleDashboard;
