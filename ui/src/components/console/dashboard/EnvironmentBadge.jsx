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

/**
 * Environment configurations
 */
const ENVIRONMENTS = {
  development: {
    label: 'Dev',
    fullLabel: 'Development',
    color: 'info',
    icon: DeveloperModeIcon,
    warning: false,
    description: 'Development environment for testing',
  },
  staging: {
    label: 'Staging',
    fullLabel: 'Staging',
    color: 'warning',
    icon: ScienceIcon,
    warning: false,
    description: 'Pre-production testing environment',
  },
  production: {
    label: 'Prod',
    fullLabel: 'Production',
    color: 'error',
    icon: ProductionQuantityLimitsIcon,
    warning: true,
    description: 'Live production environment',
  },
};

/**
 * Environment Badge Component
 */
export function EnvironmentBadge({ 
  environment = 'development', 
  onEnvironmentChange,
  organizationId,
  showSwitcher = true,
}) {
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  const currentEnv = ENVIRONMENTS[environment] || ENVIRONMENTS.development;
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
        title={showSwitcher ? `Click to switch environment • ${currentEnv.description}` : currentEnv.description}
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
  const currentEnv = ENVIRONMENTS[environment] || ENVIRONMENTS.development;

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
        <strong>Production Environment</strong>
        <Box component="span" sx={{ ml: 1 }}>
          You are operating in the live production environment. Changes will affect real users and data.
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
  environment = 'development',
  organizationId,
  onEnvironmentChange,
  showSwitcher = true,
}) {
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
            Operating As
          </Box>
        </Box>
        <Box sx={{ fontWeight: 600, fontSize: '1rem', mt: 0.5 }}>
          {organizationName || 'Organization'}
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
