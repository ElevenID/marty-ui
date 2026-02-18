/**
 * Setup Readiness Panel
 * 
 * Displays the canonical setup progression:
 * Trust → Template → Policy → Deployment → Flow
 * 
 * Shows visual state for each step: ✔ (ready), ⚠ (blocked), ○ (missing)
 */

import {
  Box,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button,
  Tooltip,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

import { ReadinessState } from '../../../config/dashboardRules';

const getResourceConfig = (t) => ({
  trust: {
    label: t('setupReadiness.trustProfile.label'),
    icon: VerifiedUserIcon,
    path: '/console/org/trust/profiles',
    tooltip: t('setupReadiness.trustProfile.tooltip'),
  },
  template: {
    label: t('setupReadiness.credentialTemplate.label'),
    icon: DescriptionIcon,
    path: '/console/org/templates/credentials',
    tooltip: t('setupReadiness.credentialTemplate.tooltip'),
  },
  policy: {
    label: t('setupReadiness.presentationPolicy.label'),
    icon: PolicyIcon,
    path: '/console/org/policies/presentation',
    tooltip: t('setupReadiness.presentationPolicy.tooltip'),
  },
  deployment: {
    label: t('setupReadiness.deploymentProfile.label'),
    icon: CloudUploadIcon,
    path: '/console/org/deploy/profiles',
    tooltip: t('setupReadiness.deploymentProfile.tooltip'),
  },
  flow: {
    label: t('setupReadiness.flowDefinition.label'),
    icon: AccountTreeIcon,
    path: '/console/org/flows/definitions',
    tooltip: t('setupReadiness.flowDefinition.tooltip'),
  },
});

/**
 * State indicator icon
 */
function StateIndicator({ state }) {
  switch (state) {
    case ReadinessState.READY:
      return <CheckCircleIcon color="success" fontSize="small" />;
    case ReadinessState.BLOCKED:
      return <WarningIcon color="warning" fontSize="small" />;
    case ReadinessState.MISSING:
    default:
      return <RadioButtonUncheckedIcon color="disabled" fontSize="small" />;
  }
}

/**
 * Readiness row
 */
function ReadinessRow({ resourceKey, readiness }) {
  const { t } = useTranslation('console');
  const config = getResourceConfig(t)[resourceKey];
  const Icon = config.icon;
  const { state, message, action, path, dependencyBlocked } = readiness;

  const rowContent = (
    <ListItem
      component={Link}
      to={config.path}
      sx={{
        py: 1.5,
        opacity: dependencyBlocked ? 0.6 : 1,
        cursor: 'pointer',
        textDecoration: 'none',
        color: 'inherit',
        '&:hover': {
          bgcolor: 'action.hover',
        },
      }}
    >
      <ListItemIcon sx={{ minWidth: 36 }}>
        <StateIndicator state={state} />
      </ListItemIcon>
      <ListItemIcon sx={{ minWidth: 40 }}>
        <Icon color={state === ReadinessState.READY ? 'primary' : 'action'} />
      </ListItemIcon>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body1" fontWeight={500}>
              {config.label}
            </Typography>
            <Tooltip title={config.tooltip} placement="top">
              <InfoOutlinedIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            </Tooltip>
            {state === ReadinessState.READY && (
              <Typography variant="caption" color="success.main" fontWeight={500}>
                {t('setupReadiness.stateReady')}
              </Typography>
            )}
            {state === ReadinessState.BLOCKED && (
              <Typography variant="caption" color="warning.main" fontWeight={500}>
                {t('setupReadiness.stateBlocked')}
              </Typography>
            )}
            {state === ReadinessState.MISSING && !dependencyBlocked && (
              <Typography variant="caption" color="text.secondary" fontWeight={500}>
                {t('setupReadiness.stateMissing')}
              </Typography>
            )}
          </Box>
        }
        secondary={message}
        secondaryTypographyProps={{ variant: 'caption' }}
      />
      {action && path && !dependencyBlocked && (
        <Button
          size="small"
          component={Link}
          to={path}
          endIcon={<ArrowForwardIcon />}
          variant={state === ReadinessState.BLOCKED ? 'contained' : 'outlined'}
          color={state === ReadinessState.BLOCKED ? 'warning' : 'primary'}
          onClick={(e) => e.stopPropagation()}
        >
          {action}
        </Button>
      )}
    </ListItem>
  );

  // Wrap in tooltip if dependency blocked
  if (dependencyBlocked) {
    return (
      <Tooltip title={t('setupReadiness.dependencyBlocked')} placement="left">
        <Box>{rowContent}</Box>
      </Tooltip>
    );
  }

  return rowContent;
}

/**
 * Setup Readiness Panel Component
 */
export function SetupReadinessPanel({ readiness, loading }) {
  const { t } = useTranslation('console');
  
  if (loading) {
    return null; // Parent handles loading state
  }

  const resourceOrder = ['trust', 'template', 'policy', 'deployment', 'flow'];

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        {t('setupReadiness.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('setupReadiness.description')}
      </Typography>
      <List disablePadding>
        {resourceOrder.map((key, index) => (
          <Box key={key}>
            <ReadinessRow
              resourceKey={key}
              readiness={readiness[key]}
            />
            {index < resourceOrder.length - 1 && (
              <Box
                sx={{
                  ml: 2.5,
                  pl: 2,
                  borderLeft: '2px solid',
                  borderColor: 'divider',
                  height: 8,
                }}
              />
            )}
          </Box>
        ))}
      </List>
    </Paper>
  );
}
