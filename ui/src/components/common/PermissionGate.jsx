import React from 'react';
import { Box, Button, Tooltip, Typography } from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import { useTranslation } from 'react-i18next';
import { usePermissions } from '../../hooks/usePermissions';

/**
 * PermissionGate - Conditionally render children based on permissions
 * 
 * @param {Object} props
 * @param {string} props.resource - Resource type to check
 * @param {string} props.action - Action to check (view, create, edit, delete, execute)
 * @param {React.ReactNode} props.children - Content to render if permission granted
 * @param {React.ReactNode} [props.fallback] - Content to render if permission denied
 * @param {boolean} [props.showLocked] - Show locked indicator instead of hiding (default: false)
 */
export function PermissionGate({ 
  resource, 
  action, 
  children, 
  fallback = null,
  showLocked = false,
}) {
  const { can, getPermissionMessage } = usePermissions();

  const hasPermission = can(resource, action);

  if (hasPermission) {
    return <>{children}</>;
  }

  if (showLocked) {
    return (
      <Tooltip title={getPermissionMessage(action)}>
        <Box sx={{ position: 'relative', display: 'inline-block' }}>
          {children}
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor: 'rgba(255, 255, 255, 0.8)',
              cursor: 'not-allowed',
              '&:hover': {
                bgcolor: 'rgba(255, 255, 255, 0.9)',
              },
            }}
          >
            <LockIcon color="disabled" />
          </Box>
        </Box>
      </Tooltip>
    );
  }

  return <>{fallback}</>;
}

/**
 * PermissionButton - Button that's automatically disabled if user lacks permission
 * 
 * @param {Object} props - All Button props plus permission props
 * @param {string} props.resource - Resource type to check
 * @param {string} props.action - Action to check
 * @param {string} [props.deniedMessage] - Custom message for disabled state
 */
export function PermissionButton({ 
  resource, 
  action, 
  deniedMessage,
  children,
  ...buttonProps 
}) {
  const { can, getPermissionMessage } = usePermissions();

  const hasPermission = can(resource, action);
  const message = deniedMessage || getPermissionMessage(action);

  if (!hasPermission) {
    return (
      <Tooltip title={message}>
        <span>
          <Button {...buttonProps} disabled>
            {children}
          </Button>
        </span>
      </Tooltip>
    );
  }

  return <Button {...buttonProps}>{children}</Button>;
}

/**
 * PermissionAlert - Show permission denied message
 * 
 * @param {Object} props
 * @param {string} props.resource - Resource type
 * @param {string} props.action - Action that was denied
 */
export function PermissionAlert({ resource, action }) {
  const { t } = useTranslation('common');
  const { getPermissionMessage } = usePermissions();

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '300px',
        p: 4,
      }}
    >
      <LockIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
      <Typography variant="h6" gutterBottom>
        {t('permissions.denied')}
      </Typography>
      <Typography variant="body1" color="text.secondary" textAlign="center">
        {getPermissionMessage(action)}
      </Typography>
    </Box>
  );
}
