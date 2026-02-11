import { useState, useEffect } from 'react';
import { Alert, Button, Box, Typography, LinearProgress } from '@mui/material';
import { Link } from 'react-router-dom';
import RocketLaunchIcon from '@mui/icons-material/RocketLaunch';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import CloseIcon from '@mui/icons-material/Close';

/**
 * GuidedSetupBanner - Shows a persistent banner prompting users to complete setup
 * 
 * Appears on dashboard when setup is incomplete. Dismissible but will reappear
 * until setup is complete.
 */
function GuidedSetupBanner({ readiness, onDismiss }) {
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    // Check if user has dismissed this banner in this session
    const isDismissed = sessionStorage.getItem('setup-banner-dismissed');
    setDismissed(isDismissed === 'true');
  }, []);

  // Calculate setup progress
  const totalSteps = 5; // trust, template, policy, deployment, flow
  const completedSteps = [
    readiness.trust?.state === 'READY',
    readiness.template?.state === 'READY',
    readiness.policy?.state === 'READY',
    readiness.deployment?.state === 'READY',
    readiness.flow?.state === 'READY',
  ].filter(Boolean).length;

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
  if (isComplete || dismissed) return null;

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
          Dismiss
        </Button>
      }
      sx={{ mb: 3 }}
    >
      <Box>
        <Typography variant="subtitle1" fontWeight={600} gutterBottom>
          {isStarted ? 'Resume Organization Setup' : 'Get Started with Guided Setup'}
        </Typography>
        <Typography variant="body2" paragraph>
          {isStarted
            ? `You're ${completedSteps} of ${totalSteps} steps complete. Continue the guided setup to finish configuring your organization.`
            : 'Walk through a step-by-step wizard to configure trust profiles, templates, policies, deployment, and flows.'}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Box sx={{ flex: 1 }}>
            <LinearProgress variant="determinate" value={progress} />
          </Box>
          <Typography variant="caption" color="text.secondary">
            {completedSteps}/{totalSteps} steps
          </Typography>
        </Box>
        <Button
          component={Link}
          to="/console/setup-wizard"
          variant="contained"
          size="small"
          startIcon={isStarted ? <PlayArrowIcon /> : <RocketLaunchIcon />}
        >
          {isStarted ? 'Resume Setup' : 'Start Guided Setup'}
        </Button>
      </Box>
    </Alert>
  );
}

export default GuidedSetupBanner;
