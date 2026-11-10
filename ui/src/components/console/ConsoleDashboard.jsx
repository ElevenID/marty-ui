/**
 * Console Dashboard
 * 
 * Dashboard sections available to the current organization member.
 * Shows status, alerts, and next step guidance.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
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
import { Link, useNavigate } from 'react-router';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { useAuth } from '../../hooks/useAuth';
import { usePermissions } from '../../hooks/usePermissions';
import { useConsole } from '../../contexts/ConsoleContext';
import { useDashboardData } from '../../hooks/useDashboardData';
import { useSSE } from '../../hooks/useSSE';
import { DASHBOARD_QUICK_ACTIONS } from '../../config/navigation';
import { computeSetupReadiness, computeBlockers, computeQuickActionVisibility } from '../../config/dashboardRules';
import { getDashboardAccess } from '../../config/dashboardAccess';
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
import DashboardErrorAlert from './dashboard/DashboardErrorAlert';
import { runHostedPilotPurge, updateOrganizationEnvironment } from '../../services/dashboardApi';
import IssuanceDashboardWidget from './dashboard/IssuanceDashboardWidget';
import { EVENT_TYPES } from '../../services/sseService';

const ACTIVITY_EVENT_TYPES = [
  EVENT_TYPES.CREDENTIAL_ISSUED,
  EVENT_TYPES.CREDENTIAL_REVOKED,
  EVENT_TYPES.APPLICATION_SUBMITTED,
  EVENT_TYPES.APPLICATION_APPROVED,
  EVENT_TYPES.APPLICATION_REJECTED,
  EVENT_TYPES.FLOW_EXECUTION_COMPLETED,
  EVENT_TYPES.FLOW_EXECUTION_FAILED,
  EVENT_TYPES.VERIFICATION_COMPLETED,
];

const EMPTY_RETENTION_COUNTS = {
  issuanceTransactions: 0,
  applications: 0,
  authorizationSessions: 0,
  issuanceEvents: 0,
  issuedCredentials: 0,
  total: 0,
};

const SHOULD_LOG_DASHBOARD_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function logDashboardError(message, error) {
  if (SHOULD_LOG_DASHBOARD_DIAGNOSTICS) {
    console.error(message, error);
  }
}

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

function HostedPilotRetentionBanner({ lifecycle, purging, purgeFeedback, onPurge, canPurge = false }) {
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
        action={hasEligibleRecords && canPurge ? (
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

function ConsoleDashboardContent() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { can, roles = [], isLoading: permissionsLoading } = usePermissions();
  const {
    user,
    organizationName: authOrganizationName,
    isAdministrator,
  } = useAuth();
  const { activeOrgId, memberships } = useConsole();
  const organizationId = activeOrgId;
  const organizationName = useMemo(() => {
    const activeMembership = (memberships || []).find((organization) => organization.id === organizationId);
    return activeMembership?.display_name
      || activeMembership?.name
      || authOrganizationName
      || t('dashboard.organizationFallbackName', { defaultValue: 'Organization' });
  }, [authOrganizationName, memberships, organizationId, t]);
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const access = useMemo(() => getDashboardAccess(can, permissionsLoading), [can, permissionsLoading]);
  const { data, loading, error, refetch } = useDashboardData(access, permissionsLoading);
  const canEditOrganization = !permissionsLoading && can('organization', 'edit');
  const environmentScope = useMemo(() => ({ organizationId }), [organizationId]);
  const currentEnvironmentScope = useRef(environmentScope);
  currentEnvironmentScope.current = environmentScope;
  const environmentRequest = useRef(0);
  const [environmentChange, setEnvironmentChange] = useState(null);
  const currentEnvironmentChange = environmentChange?.scope === environmentScope ? environmentChange : null;
  const [purgingPilotData, setPurgingPilotData] = useState(false);
  const [purgeFeedback, setPurgeFeedback] = useState(null);
  const [setupIntent, setSetupIntent] = useState(null);

  // Compute setup readiness and blockers
  const readiness = useMemo(() => computeSetupReadiness({
    ...data,
    setupIntent: setupIntent || data.setupIntent,
  }), [data, setupIntent]);
  const blockers = useMemo(() => computeBlockers(readiness), [readiness]);
  const quickActionVisibility = useMemo(() => computeQuickActionVisibility(readiness), [readiness]);
  const dashboardErrors = data.dashboardErrors || {};
  const healthError = ['trustProfiles', 'templates', 'policies', 'deployments', 'flows']
    .map((key) => data.resourceErrors?.[key]).find(Boolean);
  const environmentUnavailable = Boolean(dashboardErrors.environment);
  const displayEnvironment = environmentUnavailable ? 'unknown' : (data.environment ?? 'unset');
  const canSwitchEnvironment = Boolean(organizationId && access.environment && !environmentUnavailable
    && canEditOrganization && !currentEnvironmentChange?.pending);

  useEffect(() => () => { environmentRequest.current += 1; }, [environmentScope]);

  // Filter visible quick actions
  const visibleQuickActions = useMemo(() => {
    return DASHBOARD_QUICK_ACTIONS.adminVendor.filter(
      (action) => access.setupOverview && quickActionVisibility[action.id]?.visible === true
        && access.actions[action.id] === true
    );
  }, [quickActionVisibility, access]);

  // Handle environment change
  const handleEnvironmentChange = async (newEnv) => {
    if (!canSwitchEnvironment) {
      return;
    }

    const request = ++environmentRequest.current;
    const applies = () => currentEnvironmentScope.current === environmentScope
      && environmentRequest.current === request;
    setEnvironmentChange({ scope: environmentScope, environment: newEnv, pending: true, error: null });
    try {
      await updateOrganizationEnvironment(organizationId, newEnv);
      if (applies()) {
        setEnvironmentChange(null);
        refetch();
      }
    } catch (error) {
      if (applies()) {
        setEnvironmentChange({ scope: environmentScope, environment: newEnv, pending: false, error });
        logDashboardError('Failed to update environment:', error);
      }
    }
  };

  // Handle quick action clicks
  const handleQuickAction = (actionId) => {
    if (!visibleQuickActions.some((action) => action.id === actionId)) return;
    switch (actionId) {
      case 'register-signing-service':
        navigate('/console/org/operator/key-management/services/new');
        break;
      case 'create-issuer-identity':
        navigate('/console/org/deploy/issuer-identity/new');
        break;
      case 'create-trust-profile':
        navigate('/console/org/trust/profiles/new');
        break;
      case 'create-template':
        navigate('/console/org/templates/credentials/new');
        break;
      case 'create-policy':
        navigate('/console/org/policies/presentation/new');
        break;
      case 'generate-api-key':
        navigate('/console/org/api-keys');
        break;
      case 'create-flow':
        navigate('/console/org/flows/definitions/new');
        break;
      default:
        break;
    }
  };

  const handleHostedPilotPurge = async () => {
    if (!canEditOrganization || purgingPilotData) return;
    if (!organizationId) {
      setPurgeFeedback({
        severity: 'error',
        message: 'Select an organization before purging Hosted Pilot data.',
      });
      return;
    }

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
    return access.setupOverview && access.runtimeStatus && readiness.flow?.state === 'ready' &&
           data.runtimeStatus?.canIssue && 
           data.runtimeStatus?.canVerify;
  }, [access.setupOverview, access.runtimeStatus, readiness, data.runtimeStatus]);

  const subscriptions = useMemo(() => access.criticalEvents
    ? ACTIVITY_EVENT_TYPES
    : access.issuanceMetrics && isOperational ? [EVENT_TYPES.CREDENTIAL_ISSUED] : [],
  [access.criticalEvents, access.issuanceMetrics, isOperational]);
  useSSE(access.notifications && subscriptions.length > 0 ? organizationId : null, principalId, subscriptions);

  if (loading || permissionsLoading) {
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

  const userRole = isAdministrator ? t('common:userTypes.administrator') : roles
    .map((role) => typeof role === 'string' ? role : role.display_name || role.name)
    .filter(Boolean).join(', ');
  const welcomeName = user?.name?.trim()
    || [user?.given_name, user?.family_name].filter(Boolean).join(' ');
  const limitedAccess = !access.setupOverview || !access.applicantStats || !access.criticalEvents || !access.teamData;

  return (
    <Box data-testid="console.dashboard.page">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          {t('dashboard.title')}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="body1" color="text.secondary">
            {welcomeName ? t('dashboard.welcomeWithName', { name: welcomeName }) : t('dashboard.welcome')}
          </Typography>
          <Chip
            label={userRole ? t('dashboard.roleLabel', { role: userRole }) : 'Organization Console'}
            size="small"
            color="primary"
            variant="outlined"
          />
        </Box>
      </Box>

      {limitedAccess && (
        <Alert severity="info" sx={{ mb: 3 }}>
          This dashboard shows the sections available to your role. Additional access is required to view the other sections.
        </Alert>
      )}

      {/* Environment Context & Warning */}
      {dashboardErrors.environment ? (
        <Box sx={{ mb: 2 }}>
          <DashboardErrorAlert
            title="Environment unavailable"
            error={dashboardErrors.environment}
            onRetry={refetch}
            fallback="Organization environment could not be loaded from the organization service."
          />
        </Box>
      ) : null}
      {currentEnvironmentChange?.error ? (
        <Box sx={{ mb: 2 }}>
          <DashboardErrorAlert
            title="Environment change failed"
            error={currentEnvironmentChange.error}
            onRetry={canSwitchEnvironment ? () => handleEnvironmentChange(currentEnvironmentChange.environment) : undefined}
            fallback="The organization's environment could not be updated."
          />
        </Box>
      ) : null}
      {access.environment && <>
      <EnvironmentContext
        key={organizationId}
        organizationName={organizationName}
        environment={displayEnvironment}
        organizationId={organizationId}
        onEnvironmentChange={handleEnvironmentChange}
        showSwitcher={canSwitchEnvironment}
      />
      <Box sx={{ mt: 2 }}>
        <EnvironmentWarningBanner environment={displayEnvironment} />
      </Box>
      </>}
      {access.lifecycle && <HostedPilotRetentionBanner
        lifecycle={data.lifecycle}
        purging={purgingPilotData}
        purgeFeedback={purgeFeedback}
        onPurge={handleHostedPilotPurge}
        canPurge={canEditOrganization}
      />}

      {/* Guided Setup Banner */}
      {access.setupOverview && <GuidedSetupBanner readiness={readiness} />}

      {/* Organization Health Overview */}
      {access.healthOverview && (healthError ? (
        <DashboardErrorAlert title="Organization overview unavailable" error={healthError} onRetry={refetch} />
      ) : <OrganizationHealthPanel
        data={data}
        organizationName={organizationName}
        isActive={true}
      />)}

      {/* Applicant Lifecycle Stats */}
      {access.applicantStats && <ApplicantStatsCard />}

      {/* System Status Bar */}
      <SystemStatusBar systemHealth={data.systemHealth} canViewAudit={access.criticalEvents} />

      {/* Critical Events */}
      {access.criticalEvents && <CriticalEventsPanel
        events={data.criticalEvents}
        loading={loading}
        error={dashboardErrors.criticalEvents}
        onRetry={refetch}
      />}

      {/* Runtime Readiness */}
      {access.runtimeStatus && <RuntimeReadinessPanel
        runtimeStatus={data.runtimeStatus}
        error={dashboardErrors.runtimeStatus}
        onRetry={refetch}
      />}

      {/* Credential Issuance Widget */}
      {isOperational && access.issuanceMetrics && (
        <Box sx={{ mb: 4 }}>
          <IssuanceDashboardWidget compact={false} />
        </Box>
      )}

      {/* Team Snapshot */}
      {access.teamData && <TeamSnapshotPanel
        teamData={data.teamData}
        error={dashboardErrors.teamData}
        onRetry={refetch}
      />}

      {/* Blocking Issues */}
      {access.setupOverview && <BlockingIssuesPanel blockers={blockers} />}

      {/* Setup Readiness */}
      {access.setupOverview && <SetupReadinessPanel
        readiness={readiness}
        loading={loading}
        onIntentChange={setSetupIntent}
      />}

      {/* Setup Complete / Operational Message */}
      {isOperational && (
        <Paper sx={{ p: 3, mb: 4, bgcolor: 'success.light', color: 'success.contrastText' }}>
          <Typography variant="h6" gutterBottom>
            {t('dashboard.operationalTitle')}
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
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
            {access.criticalEvents && <Button
              variant="outlined"
              component={Link}
              to="/console/org/audit"
              sx={{ borderColor: 'success.dark', color: 'success.dark' }}
            >
              {t('dashboard.viewAudit')}
            </Button>}
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
                <Grid size={{ xs: 12, sm: 6, md: 4, lg: 2.4 }} key={action.id}>
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
      {access.criticalEvents && <RecentActivityPanel />}

      {/* Developer Quick Start */}
      {access.integrationInfo && <DeveloperQuickStartPanel canViewApiKeys={access.apiKeys} />}
    </Box>
  );
}

function ConsoleDashboard() {
  const { user } = useAuth();
  const { activeOrgId } = useConsole();
  const principalId = user?.user_id || user?.sub || user?.id || null;
  return <ConsoleDashboardContent key={JSON.stringify([principalId, activeOrgId])} />;
}

export default ConsoleDashboard;
