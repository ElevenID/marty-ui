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
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Button,
  Tooltip,
  Tabs,
  Tab,
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
import LocalShippingIcon from '@mui/icons-material/LocalShipping';
import SecurityIcon from '@mui/icons-material/Security';

import { ReadinessState, SETUP_ORDER } from '../../../config/dashboardRules';

const getResourceConfig = (t) => ({
  compliance: {
    label: t('setupReadiness.complianceProfile.label'),
    icon: PolicyIcon,
    path: '/console/org/policies/compliance',
    tooltip: t('setupReadiness.complianceProfile.tooltip'),
  },
  issuer: {
    label: 'Issuer Identity / KMS',
    icon: CloudUploadIcon,
    path: '/console/org/deploy/issuer-identity',
    tooltip: 'Issuer identity and signing services required for production issuance.',
  },
  applicationTemplate: {
    label: 'Application Template',
    icon: DescriptionIcon,
    path: '/console/org/templates/applications',
    tooltip: 'Defines the application intake form and checks before credential approval.',
  },
  policySet: {
    label: 'Approval Policy Set',
    icon: PolicyIcon,
    path: '/console/org/policies/sets',
    tooltip: 'Defines auditable Cedar rules used to govern approval decisions.',
  },
  physicalCapability: {
    label: 'Physical Issuance Capability',
    icon: SecurityIcon,
    path: '/console/org/deploy/key-management',
    tooltip: 'Requires document signing, encrypted artifact storage, and a configured personalization bureau.',
  },
  deliveryDestination: {
    label: 'Production Destination',
    icon: LocalShippingIcon,
    path: '/console/org/connect/delivery-destinations',
    tooltip: 'Identifies the approved personalization bureau or physical production destination.',
  },
  revocation: {
    label: 'Revocation Profile',
    icon: PolicyIcon,
    path: '/console/org/policies/revocation',
    tooltip: 'Defines revocation or renewal controls for credential lifecycle operations.',
  },
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
  const actionButton = action && path && !dependencyBlocked ? (
    <Button
      size="small"
      component={Link}
      to={path}
      endIcon={<ArrowForwardIcon />}
      variant={state === ReadinessState.BLOCKED ? 'contained' : 'outlined'}
      color={state === ReadinessState.BLOCKED ? 'warning' : 'primary'}
    >
      {action}
    </Button>
  ) : null;

  const rowContent = (
    <ListItem
      disablePadding
      sx={{
        opacity: dependencyBlocked ? 0.6 : 1,
        alignItems: 'stretch',
      }}
    >
      <ListItemButton
        component={Link}
        to={config.path}
        sx={{
          py: 1.5,
          textDecoration: 'none',
          color: 'inherit',
          flexGrow: 1,
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
          slotProps={{
            secondary: { variant: 'caption' }
          }}
        />
      </ListItemButton>
      {actionButton && (
        <Box sx={{ display: 'flex', alignItems: 'center', pr: 2 }}>
          {actionButton}
        </Box>
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
export function SetupReadinessPanel({ readiness, loading, onIntentChange }) {
  const { t } = useTranslation('console');
  
  if (loading) {
    return null; // Parent handles loading state
  }

  const hasIntentReadiness = Boolean(readiness?.intents?.[readiness.activeIntent]);
  const activeIntent = hasIntentReadiness ? readiness.activeIntent : null;
  const activeIntentReadiness = hasIntentReadiness ? readiness.intents[activeIntent] : null;
  const displayReadiness = activeIntentReadiness?.steps || readiness || {};
  const resourceOrder = activeIntentReadiness
    ? activeIntentReadiness.order.filter((key) => displayReadiness?.[key])
    : SETUP_ORDER.filter((key) => displayReadiness?.[key]);
  const intentEntries = hasIntentReadiness ? Object.values(readiness.intents) : [];

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, alignItems: 'flex-start', mb: 1 }}>
        <Box>
          <Typography variant="h6" gutterBottom>
            {activeIntentReadiness
              ? `${t('setupReadiness.title')}: ${activeIntentReadiness.label}`
              : t('setupReadiness.title')}
          </Typography>
          {activeIntentReadiness?.description && (
            <Typography variant="body2" color="text.secondary">
              {activeIntentReadiness.description}
            </Typography>
          )}
        </Box>
      </Box>
      {intentEntries.length > 0 && (
        <Tabs
          value={activeIntent}
          onChange={(_, value) => onIntentChange?.(value)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
        >
          {intentEntries.map((intent) => (
            <Tab
              key={intent.id}
              value={intent.id}
              label={intent.label}
            />
          ))}
        </Tabs>
      )}
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('setupReadiness.description')}
      </Typography>
      <List disablePadding>
        {resourceOrder.map((key, index) => (
          <Box key={key}>
            <ReadinessRow
              resourceKey={key}
              readiness={displayReadiness[key]}
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
