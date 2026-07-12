import { useState, useEffect } from 'react';
import { Alert, Button, Box, Typography, LinearProgress } from '@mui/material';
import { Link } from 'react-router-dom';
import RocketLaunchIcon from '@mui/icons-material/RocketLaunch';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import CloseIcon from '@mui/icons-material/Close';
import { useTranslation } from 'react-i18next';
import { ReadinessState, SETUP_ORDER } from '../../../config/dashboardRules';

/**
 * GuidedSetupBanner - Shows a persistent banner prompting users to complete setup
 * 
 * Appears on dashboard when setup is incomplete. Dismissible but will reappear
 * until setup is complete.
 */
function GuidedSetupBanner({ readiness, onDismiss }) {
  const { t } = useTranslation('console');
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    // Check if user has dismissed this banner in this session
    const isDismissed = sessionStorage.getItem('setup-banner-dismissed');
    setDismissed(isDismissed === 'true');
  }, []);

  const activeIntentReadiness = readiness?.intents?.[readiness?.activeIntent];
  const steps = activeIntentReadiness?.steps || readiness || {};
  const order = activeIntentReadiness?.order || SETUP_ORDER;

  // Calculate setup progress for the selected recipe.
  const totalSteps = order.length;
  const completedSteps = order.filter(
    (step) => steps?.[step]?.state === ReadinessState.READY
  ).length;
  const hasServiceError = order.some((step) => steps?.[step]?.serviceError);
  const nextSetupPath = order
    .map((step) => steps?.[step])
    .find((step) => step?.state !== ReadinessState.READY && step?.path && !step?.dependencyBlocked)
    ?.path;

  const progress = (completedSteps / totalSteps) * 100;
  const isComplete = completedSteps === totalSteps;

  // Check if setup has been started
  const isStarted = completedSteps > 0;

  const handleDismiss = () => {
    sessionStorage.setItem('setup-banner-dismissed', 'true');
    setDismissed(true);
    onDismiss?.();
  };

  // Don't show if complete or dismissed
  if (isComplete || dismissed || hasServiceError || !nextSetupPath) return null;

  return (
    <Alert
      severity={isStarted ? 'info' : 'warning'}
      icon={<RocketLaunchIcon />}
      action={
        <Button
          color="inherit"
          size="small"
          onClick={handleDismiss}
          startIcon={<CloseIcon />}
        >
          {t('dashboard.guidedSetupBanner.dismiss')}
        </Button>
      }
      sx={{ mb: 3 }}
    >
      <Box>
        <Typography variant="subtitle1" fontWeight={600} gutterBottom>
          {isStarted ? t('dashboard.guidedSetupBanner.resumeSetup') : t('dashboard.guidedSetupBanner.getStarted')}
        </Typography>
        <Typography variant="body2" paragraph>
          {isStarted
            ? t('dashboard.guidedSetupBanner.resumeProgress', { completed: completedSteps, total: totalSteps })
            : t('dashboard.guidedSetupBanner.startDescription')}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Box sx={{ flex: 1 }}>
            <LinearProgress variant="determinate" value={progress} />
          </Box>
          <Typography variant="caption" color="text.secondary">
            {t('dashboard.guidedSetupBanner.stepsProgress', { completed: completedSteps, total: totalSteps })}
          </Typography>
        </Box>
        <Button
          component={Link}
          to={nextSetupPath}
          variant="contained"
          size="small"
          startIcon={isStarted ? <PlayArrowIcon /> : <RocketLaunchIcon />}
        >
          {isStarted ? t('dashboard.guidedSetupBanner.resumeButton') : t('dashboard.guidedSetupBanner.startButton')}
        </Button>
      </Box>
    </Alert>
  );
}

export default GuidedSetupBanner;
