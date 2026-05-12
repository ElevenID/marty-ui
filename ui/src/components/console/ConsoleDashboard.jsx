/**
 * Console Dashboard
 * 
 * Main dashboard for Admin/Vendor users.
 * Shows status, alerts, and next step guidance.
 */

import { useMemo, useState } from 'react';
import {
  Alert,
  AlertTitle,
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
import { Link, useNavigate } from 'react-router-dom';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { useAuth } from '../../hooks/useAuth';
import { useDashboardData } from '../../hooks/useDashboardData';
import { useSSE } from '../../hooks/useSSE';
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
import { runHostedPilotPurge, updateOrganizationEnvironment } from '../../services/dashboardApi';
import CreateTemplateDrawer from './templates/CreateTemplateDrawer';
import CreatePolicyDrawer from './policies/CreatePolicyDrawer';
import CreateDeploymentDrawer from './deployments/CreateDeploymentDrawer';
import CreateFlowDrawer from './flows/CreateFlowDrawer';
import IssuanceDashboardWidget from './dashboard/IssuanceDashboardWidget';

const EMPTY_RETENTION_COUNTS = {
  issuanceTransactions: 0,
  applications: 0,
  authorizationSessions: 0,
  issuanceEvents: 0,
  issuedCredentials: 0,
  total: 0,
};

function formatRelativeCountdown(targetIso) {
  if (!targetIso) {
    return null;
  }

  const deltaMs = new Date(targetIso).getTime() - Date.now();
  if (Number.isNaN(deltaMs)) {
    return null;
  }

  if (deltaMs <= 0) {
    return 'now';
  }

  const totalHours = Math.ceil(deltaMs / (1000 * 60 * 60));
  if (totalHours < 24) {
    return `${totalHours} hour${totalHours === 1 ? '' : 's'}`;
  }

  const totalDays = Math.ceil(totalHours / 24);
  return `${totalDays} day${totalDays === 1 ? '' : 's'}`;
}

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return null;
  }

  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }

  return parsed.toLocaleString();
}

function HostedPilotRetentionBanner({ lifecycle, purging, purgeFeedback, onPurge }) {
  const pilotRetention = lifecycle?.pilotRetention;
  if (!pilotRetention?.enabled) {
    return null;
  }

  const eligibleForPurge = pilotRetention.eligibleForPurge || EMPTY_RETENTION_COUNTS;
  const hasEligibleRecords = eligibleForPurge.total > 0;
  const countdownLabel = formatRelativeCountdown(pilotRetention.nextExpiryAt);
  const lastPurgedLabel = formatTimestamp(purgeFeedback?.purgedAt || pilotRetention.lastPurgedAt);

  return (
    <Box sx={{ mt: 2 }}>
      <Alert
        severity={hasEligibleRecords ? 'warning' : 'info'}
        action={hasEligibleRecords ? (
          <Button
            color="inherit"
            size="small"
            variant="outlined"
            onClick={onPurge}
            disabled={purging}
          >
            {purging ? 'Purging...' : 'Purge now'}
          </Button>
        ) : null}
      >
        <AlertTitle>Hosted Pilot retention</AlertTitle>
        <Typography variant="body2">
          {hasEligibleRecords
            ? `${eligibleForPurge.total} Hosted Pilot records are older than ${pilotRetention.windowDays} days and ready to purge.`
            : countdownLabel
              ? `Next Hosted Pilot record ages out in ${countdownLabel}.`
              : `No Hosted Pilot records are close to expiry yet. New pilot data ages out after ${pilotRetention.windowDays} days.`}
        </Typography>
        {pilotRetention.scopeSummary ? (
          <Typography variant="body2" sx={{ mt: 0.75 }}>
            {pilotRetention.scopeSummary}
          </Typography>
        ) : null}
        {pilotRetention.accessBehavior ? (
          <Typography variant="body2" sx={{ mt: 0.75 }}>
            {pilotRetention.accessBehavior}
          </Typography>
        ) : null}
        {lastPurgedLabel ? (
          <Typography variant="caption" sx={{ display: 'block', mt: 1 }}>
            Last purge completed: {lastPurgedLabel}
          </Typography>
        ) : null}
      </Alert>
      {purgeFeedback?.message ? (
        <Alert severity={purgeFeedback.severity} sx={{ mt: 1.5 }}>
          {purgeFeedback.message}
        </Alert>
      ) : null}
    </Box>
  );
}


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
  const navigate = useNavigate();
  const { user, organizationName, organizationId, isAdministrator, isVendor } = useAuth();
  const { data, loading, error, refetch } = useDashboardData();
  useSSE(organizationId);
  const [environment, setEnvironment] = useState(data.environment || 'development');
  const [activeDrawer, setActiveDrawer] = useState(null);
  const [purgingPilotData, setPurgingPilotData] = useState(false);
  const [purgeFeedback, setPurgeFeedback] = useState(null);

  // Compute setup readiness and blockers
  const readiness = useMemo(() => computeSetupReadiness(data), [data]);
  const blockers = useMemo(() => computeBlockers(readiness), [readiness]);
  const quickActionVisibility = useMemo(() => computeQuickActionVisibility(readiness), [readiness]);

  // Filter visible quick actions
  const visibleQuickActions = useMemo(() => {
    return DASHBOARD_QUICK_ACTIONS.adminVendor.filter(
      (action) => quickActionVisibility[action.id]?.visible === true
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
      case 'register-signing-service':
        navigate('/console/org/deploy/key-management/services/new');
        break;
      case 'create-issuer-identity':
        navigate('/console/org/deploy/issuer-identity');
        break;
      case 'create-trust-profile':
        navigate('/console/org/trust/profiles/new');
        break;
      case 'create-template':
        setActiveDrawer('template');
        break;
      case 'create-policy':
        setActiveDrawer('policy');
        break;
      case 'generate-api-key':
        navigate('/console/org/api-keys');
        break;
      case 'create-flow':
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

  const handleHostedPilotPurge = async () => {
    setPurgingPilotData(true);
    setPurgeFeedback(null);

    try {
      const result = await runHostedPilotPurge(organizationId);
      setPurgeFeedback({
        severity: 'success',
        message: `Purged ${result.purgedRecords.total} Hosted Pilot records.`,
        purgedAt: result.purgedAt,
      });
      if (refetch) {
        refetch();
      }
    } catch (purgeError) {
      setPurgeFeedback({
        severity: 'error',
        message: purgeError?.message || 'Failed to purge Hosted Pilot data.',
      });
    } finally {
      setPurgingPilotData(false);
    }
  };

  // Check if org is operational (setup complete + runtime ready)
  const isOperational = useMemo(() => {
    return readiness.flow?.state === 'ready' && 
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
    <Box data-testid="console.dashboard.page">
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
      <HostedPilotRetentionBanner
        lifecycle={data.lifecycle}
        purging={purgingPilotData}
        purgeFeedback={purgeFeedback}
        onPurge={handleHostedPilotPurge}
      />

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
