/**
 * Environment Badge Component
 * 
 * Shows environment awareness:
 * - Environment badge (Dev / Staging / Prod)
 * - Visual warning if operating in Prod
 * - Ability to switch environment context
 * 
 * Purpose: prevent accidental prod operations
 */

import {
  Box,
  Chip,
  Menu,
  MenuItem,
  Alert,
  Tooltip,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import { useState } from 'react';
import DeveloperModeIcon from '@mui/icons-material/DeveloperMode';
import ScienceIcon from '@mui/icons-material/Science';
import ProductionQuantityLimitsIcon from '@mui/icons-material/ProductionQuantityLimits';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import HelpOutlineIcon from '@mui/icons-material/HelpOutlined';
import { useTranslation } from 'react-i18next';

/**
 * Environment configurations factory
 */
const getEnvironments = (t) => ({
  unknown: {
    label: t('dashboard.environment.unknown', 'Unknown'),
    fullLabel: t('dashboard.environment.unknownFull', 'Environment unknown'),
    color: 'default',
    icon: HelpOutlineIcon,
    warning: false,
    description: t('dashboard.environment.unknownDescription', 'Environment could not be loaded.'),
  },
  development: {
    label: t('dashboard.environment.dev'),
    fullLabel: t('dashboard.environment.development'),
    color: 'info',
    icon: DeveloperModeIcon,
    warning: false,
    description: t('dashboard.environment.devDescription'),
  },
  staging: {
    label: t('dashboard.environment.staging'),
    fullLabel: t('dashboard.environment.stagingFull'),
    color: 'warning',
    icon: ScienceIcon,
    warning: false,
    description: t('dashboard.environment.stagingDescription'),
  },
  production: {
    label: t('dashboard.environment.prod'),
    fullLabel: t('dashboard.environment.production'),
    color: 'error',
    icon: ProductionQuantityLimitsIcon,
    warning: true,
    description: t('dashboard.environment.prodDescription'),
  },
});

/**
 * Environment Badge Component
 */
export function EnvironmentBadge({ 
  environment = 'unknown',
  onEnvironmentChange,
  organizationId,
  showSwitcher = true,
}) {
  const { t } = useTranslation('console');
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  const ENVIRONMENTS = getEnvironments(t);
  const currentEnv = ENVIRONMENTS[environment] || ENVIRONMENTS.unknown;
  const Icon = currentEnv.icon;

  const handleClick = (event) => {
    if (showSwitcher) {
      setAnchorEl(event.currentTarget);
    }
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleSelectEnvironment = (env) => {
    if (onEnvironmentChange) {
      onEnvironmentChange(env, organizationId);
    }
    handleClose();
  };

  return (
    <Box>
      <Tooltip 
        title={showSwitcher ? t('dashboard.environment.clickToSwitch', { description: currentEnv.description }) : currentEnv.description}
        placement="bottom"
      >
        <Chip
          icon={<Icon />}
          label={currentEnv.label}
          color={currentEnv.color}
          size="small"
          onClick={handleClick}
          sx={{
            fontWeight: 600,
            cursor: showSwitcher ? 'pointer' : 'default',
            '&:hover': showSwitcher ? {
              opacity: 0.8,
            } : {},
          }}
        />
      </Tooltip>

      {showSwitcher && (
        <Menu
          anchorEl={anchorEl}
          open={open}
          onClose={handleClose}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'right',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'right',
          }}
        >
          {Object.entries(ENVIRONMENTS).map(([key, config]) => {
            const EnvIcon = config.icon;
            const isSelected = key === environment;
            
            return (
              <MenuItem
                key={key}
                onClick={() => handleSelectEnvironment(key)}
                selected={isSelected}
              >
                <ListItemIcon>
                  {isSelected ? <CheckCircleIcon fontSize="small" /> : <EnvIcon fontSize="small" />}
                </ListItemIcon>
                <ListItemText
                  primary={config.fullLabel}
                  secondary={config.description}
                />
              </MenuItem>
            );
          })}
        </Menu>
      )}
    </Box>
  );
}

/**
 * Environment Warning Banner
 * Shows prominent warning when in production
 */
export function EnvironmentWarningBanner({ environment = 'development' }) {
  const { t } = useTranslation('console');
  const ENVIRONMENTS = getEnvironments(t);
  const currentEnv = ENVIRONMENTS[environment] || ENVIRONMENTS.unknown;

  if (!currentEnv.warning) {
    return null;
  }

  return (
    <Alert 
      severity="warning" 
      icon={<WarningIcon />}
      sx={{ mb: 3 }}
    >
      <Box>
        <strong>{t('dashboard.environment.warningTitle')}</strong>
        <Box component="span" sx={{ ml: 1 }}>
          {t('dashboard.environment.warningMessage')}
        </Box>
      </Box>
    </Alert>
  );
}

/**
 * Environment Context Display
 * Shows current org + environment combination
 */
export function EnvironmentContext({ 
  organizationName, 
  environment = 'unknown',
  organizationId,
  onEnvironmentChange,
  showSwitcher = true,
}) {
  const { t } = useTranslation('console');
  
  return (
    <Box sx={{ 
      display: 'flex', 
      alignItems: 'center', 
      gap: 2,
      p: 2,
      bgcolor: 'background.paper',
      borderRadius: 1,
      border: '1px solid',
      borderColor: 'divider',
    }}>
      <Box sx={{ flex: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box sx={{ 
            fontSize: '0.75rem', 
            color: 'text.secondary',
            textTransform: 'uppercase',
            letterSpacing: 1,
          }}>
            {t('dashboard.environment.operatingAs')}
          </Box>
        </Box>
        <Box sx={{ fontWeight: 600, fontSize: '1rem', mt: 0.5 }}>
          {organizationName || t('dashboard.environment.organizationFallback')}
        </Box>
      </Box>
      
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        {showSwitcher && (
          <SwapHorizIcon fontSize="small" color="action" />
        )}
        <EnvironmentBadge 
          environment={environment}
          organizationId={organizationId}
          onEnvironmentChange={onEnvironmentChange}
          showSwitcher={showSwitcher}
        />
      </Box>
    </Box>
  );
}
