/**
 * Console Dashboard
 * 
 * Main dashboard for Admin/Vendor users.
 * Shows status, alerts, and next step guidance.
 */

import { useMemo, useState } from 'react';
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
  Chip,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
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
import { OrganizationHealthPanel } from './dashboard/OrganizationHealthPanel';
import { RuntimeReadinessPanel } from './dashboard/RuntimeReadinessPanel';
import { CriticalEventsPanel } from './dashboard/CriticalEventsPanel';
import { TeamSnapshotPanel } from './dashboard/TeamSnapshotPanel';
import { ApplicantStatsCard } from './dashboard/ApplicantStatsCard';
import { DeveloperQuickStartPanel } from './dashboard/DeveloperQuickStartPanel';
import { EnvironmentWarningBanner, EnvironmentContext } from './dashboard/EnvironmentBadge';
import GuidedSetupBanner from './dashboard/GuidedSetupBanner';
import { updateOrganizationEnvironment } from '../../services/dashboardApi';
import CreateTrustProfileDrawer from './trust/CreateTrustProfileDrawer';
import CreateTemplateDrawer from './templates/CreateTemplateDrawer';
import CreatePolicyDrawer from './policies/CreatePolicyDrawer';
import CreateDeploymentDrawer from './deployments/CreateDeploymentDrawer';
import CreateFlowDrawer from './flows/CreateFlowDrawer';
import IssuanceDashboardWidget from './dashboard/IssuanceDashboardWidget';


/**
 * Quick action card with context-aware state
 */
function QuickActionCard({ action, disabled, tooltip, onClick }) {
  const { t } = useTranslation('console');
  const Icon = action.icon;
  
  const handleClick = (e) => {
    if (onClick && !disabled) {
      e.preventDefault();
      onClick(action.id);
    }
  };
  
  const cardContent = (
    <Card 
      sx={{ 
        height: '100%',
        opacity: disabled ? 0.6 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
      }}
      onClick={handleClick}
    >
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
          component={disabled || onClick ? 'button' : Link}
          to={disabled || onClick ? undefined : action.path}
          endIcon={<ArrowForwardIcon />}
          disabled={disabled}
          onClick={handleClick}
        >
          {t('dashboard.getStarted')}
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
  const { t } = useTranslation('console');
  const { user, organizationName, organizationId, isAdministrator, isVendor } = useAuth();
  const { data, loading, error, refetch } = useDashboardData();
  const [environment, setEnvironment] = useState(data.environment || 'development');
  const [activeDrawer, setActiveDrawer] = useState(null);

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

  // Handle environment change
  const handleEnvironmentChange = async (newEnv) => {
    try {
      await updateOrganizationEnvironment(organizationId, newEnv);
      setEnvironment(newEnv);
    } catch (error) {
      console.error('Failed to update environment:', error);
    }
  };

  // Handle quick action clicks
  const handleQuickAction = (actionId) => {
    switch (actionId) {
      case 'create-trust-profile':
        setActiveDrawer('trust');
        break;
      case 'create-template':
        setActiveDrawer('template');
        break;
      case 'create-policy':
        setActiveDrawer('policy');
        break;
      case 'generate-api-key':
        setActiveDrawer('deployment');
        break;
      case 'start-verification':
        setActiveDrawer('flow');
        break;
      default:
        break;
    }
  };

  const handleDrawerClose = () => {
    setActiveDrawer(null);
  };

  const handleDrawerSuccess = () => {
    // Refresh dashboard data after successful creation
    if (refetch) {
      refetch();
    }
  };

  // Check if org is operational (setup complete + runtime ready)
  const isOperational = useMemo(() => {
    return readiness.flow?.state === 'READY' && 
           data.runtimeStatus?.canIssue && 
           data.runtimeStatus?.canVerify;
  }, [readiness, data.runtimeStatus]);

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
        <Typography color="error">{t('dashboard.errorLoading', { error })}</Typography>
      </Box>
    );
  }

  // Determine user role for display
  const userRole = isAdministrator ? t('common:userTypes.administrator') : isVendor ? t('common:userTypes.vendor') : t('common:userTypes.user');

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          {t('dashboard.title')}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="body1" color="text.secondary">
            {user?.name ? t('dashboard.welcomeWithName', { name: user.name }) : t('dashboard.welcome')}
          </Typography>
          <Chip
            label={t('dashboard.roleLabel', { role: userRole })}
            size="small"
            color="primary"
            variant="outlined"
          />
        </Box>
      </Box>

      {/* Environment Context & Warning */}
      <EnvironmentContext
        organizationName={organizationName}
        environment={environment}
        organizationId={organizationId}
        onEnvironmentChange={handleEnvironmentChange}
        showSwitcher={true}
      />
      <Box sx={{ mt: 2 }}>
        <EnvironmentWarningBanner environment={environment} />
      </Box>

      {/* Guided Setup Banner */}
      <GuidedSetupBanner readiness={readiness} />

      {/* Organization Health Overview */}
      <OrganizationHealthPanel 
        data={data}
        organizationName={organizationName}
        isActive={true}
      />

      {/* Applicant Lifecycle Stats */}
      <ApplicantStatsCard />

      {/* System Status Bar */}
      <SystemStatusBar systemHealth={data.systemHealth} />

      {/* Critical Events */}
      <CriticalEventsPanel events={data.criticalEvents} loading={loading} />

      {/* Runtime Readiness */}
      <RuntimeReadinessPanel runtimeStatus={data.runtimeStatus} />

      {/* Credential Issuance Widget */}
      {isOperational && (
        <Box sx={{ mb: 4 }}>
          <IssuanceDashboardWidget compact={false} />
        </Box>
      )}

      {/* Team Snapshot */}
      <TeamSnapshotPanel teamData={data.teamData} />

      {/* Blocking Issues */}
      <BlockingIssuesPanel blockers={blockers} />

      {/* Setup Readiness */}
      <SetupReadinessPanel readiness={readiness} loading={loading} />

      {/* Setup Complete / Operational Message */}
      {isOperational && (
        <Paper sx={{ p: 3, mb: 4, bgcolor: 'success.light', color: 'success.contrastText' }}>
          <Typography variant="h6" gutterBottom>
            {t('dashboard.operationalTitle')}
          </Typography>
          <Typography variant="body2" paragraph>
            {t('dashboard.operationalDescription')}
          </Typography>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button
              variant="contained"
              component={Link}
              to="/console/org/operate"
              endIcon={<ArrowForwardIcon />}
              sx={{ bgcolor: 'success.dark', '&:hover': { bgcolor: 'success.darker' } }}
            >
              {t('dashboard.goToOperate')}
            </Button>
            <Button
              variant="outlined"
              component={Link}
              to="/console/audit"
              sx={{ borderColor: 'success.dark', color: 'success.dark' }}
            >
              {t('dashboard.viewAudit')}
            </Button>
          </Box>
        </Paper>
      )}

      {/* Next Step - Only show if not operational and there are next valid actions */}
      {!isOperational && visibleQuickActions.length > 0 && (
        <>
          <Typography variant="h6" gutterBottom>
            {t('dashboard.nextStep')}
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
                    onClick={handleQuickAction}
                  />
                </Grid>
              );
            })}
          </Grid>
        </>
      )}

      {/* Recent Activity */}
      <RecentActivityPanel />

      {/* Developer Quick Start */}
      <DeveloperQuickStartPanel />

      {/* Resource Creation Drawers */}
      <CreateTrustProfileDrawer
        open={activeDrawer === 'trust'}
        onClose={handleDrawerClose}
        onSuccess={handleDrawerSuccess}
      />
      <CreateTemplateDrawer
        open={activeDrawer === 'template'}
        onClose={handleDrawerClose}
        onSuccess={handleDrawerSuccess}
      />
      <CreatePolicyDrawer
        open={activeDrawer === 'policy'}
        onClose={handleDrawerClose}
        onSuccess={handleDrawerSuccess}
      />
      <CreateDeploymentDrawer
        open={activeDrawer === 'deployment'}
        onClose={handleDrawerClose}
        onSuccess={handleDrawerSuccess}
      />
      <CreateFlowDrawer
        open={activeDrawer === 'flow'}
        onClose={handleDrawerClose}
        onSuccess={handleDrawerSuccess}
      />
    </Box>
  );
}

export default ConsoleDashboard;
