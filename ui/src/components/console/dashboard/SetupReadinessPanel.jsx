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

const RESOURCE_CONFIG = {
  trust: {
    label: 'Trust Profile',
    icon: VerifiedUserIcon,
    path: '/console/trust/profiles',
    tooltip: 'Defines which credential formats, issuers, and validation rules you accept',
  },
  template: {
    label: 'Credential Template',
    icon: DescriptionIcon,
    path: '/console/templates/credentials',
    tooltip: 'Defines the schema and format for credentials you issue',
  },
  policy: {
    label: 'Presentation Policy',
    icon: PolicyIcon,
    path: '/console/policies/presentation',
    tooltip: 'Defines what credentials and claims are required when verifying',
  },
  deployment: {
    label: 'Deployment Profile',
    icon: CloudUploadIcon,
    path: '/console/deploy/profiles',
    tooltip: 'Binds policies and flows to your runtime environment (APIs, kiosks, devices)',
  },
  flow: {
    label: 'Flow Definition',
    icon: AccountTreeIcon,
    path: '/console/flows/definitions',
    tooltip: 'Orchestrates verification or issuance workflows for end users',
  },
};

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
  const config = RESOURCE_CONFIG[resourceKey];
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
                Ready
              </Typography>
            )}
            {state === ReadinessState.BLOCKED && (
              <Typography variant="caption" color="warning.main" fontWeight={500}>
                Blocked
              </Typography>
            )}
            {state === ReadinessState.MISSING && !dependencyBlocked && (
              <Typography variant="caption" color="text.secondary" fontWeight={500}>
                Missing
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
      <Tooltip title="Complete previous steps first" placement="left">
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
  if (loading) {
    return null; // Parent handles loading state
  }

  const resourceOrder = ['trust', 'template', 'policy', 'deployment', 'flow'];

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        Setup Readiness
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Complete these steps in order to enable full identity operations
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
