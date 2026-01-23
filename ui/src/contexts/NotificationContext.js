/**
 * NotificationContext
 * 
 * A global notification system providing unified toast/snackbar notifications
 * across the entire application. Supports different severity levels, auto-retry
 * actions, and error code display.
 * 
 * Usage:
 *   // In a component
 *   const { showNotification, showError, showSuccess } = useNotification();
 *   
 *   // Show a simple success message
 *   showSuccess('Changes saved successfully');
 *   
 *   // Show an error with retry action
 *   showError('Failed to load data', { 
 *     recoveryAction: 'retry',
 *     onRetry: () => fetchData() 
 *   });
 *   
 *   // Show an API error response
 *   showApiError(apiResponse);
 */

import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import {
  Snackbar,
  Alert,
  AlertTitle,
  Button,
  IconButton,
  Box,
  Typography,
  Collapse,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import RefreshIcon from '@mui/icons-material/Refresh';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';


/**
 * Notification severity levels.
 */
export const NotificationSeverity = {
  SUCCESS: 'success',
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error',
};


/**
 * Recovery action types.
 */
export const RecoveryAction = {
  RETRY: 'retry',
  RETRY_WITH_BACKOFF: 'retry_with_backoff',
  REAUTHENTICATE: 'reauthenticate',
  CONTACT_SUPPORT: 'contact_support',
  FAIL_FAST: 'fail_fast',
};


/**
 * Default notification configuration.
 */
const DEFAULT_CONFIG = {
  autoHideDuration: 6000,
  position: { vertical: 'bottom', horizontal: 'center' },
  maxNotifications: 3,
};


/**
 * Create the notification context.
 */
const NotificationContext = createContext(null);


/**
 * Single notification item component.
 */
const NotificationItem = ({ 
  notification, 
  onClose, 
  onRetry,
  position,
}) => {
  const [showDetails, setShowDetails] = useState(false);
  
  const {
    id,
    message,
    title,
    severity,
    errorCode,
    requestId,
    recoveryAction,
    details,
    autoHideDuration,
  } = notification;
  
  const handleClose = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    onClose(id);
  };
  
  const handleCopyErrorId = () => {
    const textToCopy = requestId || errorCode || id;
    navigator.clipboard.writeText(textToCopy);
  };
  
  const showRetryButton = recoveryAction === RecoveryAction.RETRY || 
                          recoveryAction === RecoveryAction.RETRY_WITH_BACKOFF;
  
  const showReauthButton = recoveryAction === RecoveryAction.REAUTHENTICATE;
  
  const hasDetails = errorCode || requestId || details;
  
  return (
    <Snackbar
      open={true}
      autoHideDuration={autoHideDuration}
      onClose={handleClose}
      anchorOrigin={position}
      sx={{ position: 'relative', mt: 1 }}
    >
      <Alert
        severity={severity}
        variant="filled"
        onClose={() => onClose(id)}
        sx={{ 
          width: '100%', 
          minWidth: 300,
          maxWidth: 500,
          '& .MuiAlert-message': { width: '100%' },
        }}
        action={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {showRetryButton && onRetry && (
              <Button
                color="inherit"
                size="small"
                startIcon={<RefreshIcon />}
                onClick={() => {
                  onRetry();
                  onClose(id);
                }}
              >
                Retry
              </Button>
            )}
            {showReauthButton && (
              <Button
                color="inherit"
                size="small"
                onClick={() => {
                  window.location.href = '/login';
                }}
              >
                Log In
              </Button>
            )}
            {hasDetails && (
              <IconButton
                color="inherit"
                size="small"
                onClick={() => setShowDetails(!showDetails)}
                aria-label={showDetails ? 'Hide details' : 'Show details'}
              >
                {showDetails ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            )}
            <IconButton
              color="inherit"
              size="small"
              onClick={() => onClose(id)}
              aria-label="Close"
            >
              <CloseIcon fontSize="small" />
            </IconButton>
          </Box>
        }
      >
        {title && <AlertTitle>{title}</AlertTitle>}
        <Typography variant="body2">{message}</Typography>
        
        <Collapse in={showDetails}>
          <Box sx={{ mt: 1, pt: 1, borderTop: '1px solid rgba(255,255,255,0.3)' }}>
            {errorCode && (
              <Typography variant="caption" display="block">
                <strong>Error Code:</strong> {errorCode}
              </Typography>
            )}
            {requestId && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="caption">
                  <strong>Request ID:</strong> {requestId.substring(0, 8)}...
                </Typography>
                <IconButton
                  size="small"
                  onClick={handleCopyErrorId}
                  sx={{ color: 'inherit', p: 0.25 }}
                  aria-label="Copy request ID"
                >
                  <ContentCopyIcon sx={{ fontSize: 14 }} />
                </IconButton>
              </Box>
            )}
            {details && (
              <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                {typeof details === 'string' ? details : JSON.stringify(details)}
              </Typography>
            )}
          </Box>
        </Collapse>
      </Alert>
    </Snackbar>
  );
};


/**
 * NotificationProvider component.
 */
export function NotificationProvider({ children, config = {} }) {
  const [notifications, setNotifications] = useState([]);
  
  const mergedConfig = useMemo(() => ({
    ...DEFAULT_CONFIG,
    ...config,
  }), [config]);
  
  /**
   * Generate a unique notification ID.
   */
  const generateId = useCallback(() => {
    return `notif-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }, []);
  
  /**
   * Add a notification.
   */
  const addNotification = useCallback((notification) => {
    const id = generateId();
    const newNotification = {
      id,
      autoHideDuration: mergedConfig.autoHideDuration,
      severity: NotificationSeverity.INFO,
      ...notification,
    };
    
    setNotifications((prev) => {
      // Limit the number of notifications
      const updated = [...prev, newNotification];
      if (updated.length > mergedConfig.maxNotifications) {
        return updated.slice(-mergedConfig.maxNotifications);
      }
      return updated;
    });
    
    return id;
  }, [generateId, mergedConfig]);
  
  /**
   * Remove a notification by ID.
   */
  const removeNotification = useCallback((id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);
  
  /**
   * Clear all notifications.
   */
  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);
  
  /**
   * Show a notification with full options.
   */
  const showNotification = useCallback((options) => {
    if (typeof options === 'string') {
      return addNotification({ message: options });
    }
    return addNotification(options);
  }, [addNotification]);
  
  /**
   * Show a success notification.
   */
  const showSuccess = useCallback((message, options = {}) => {
    return addNotification({
      message,
      severity: NotificationSeverity.SUCCESS,
      autoHideDuration: 4000,
      ...options,
    });
  }, [addNotification]);
  
  /**
   * Show an info notification.
   */
  const showInfo = useCallback((message, options = {}) => {
    return addNotification({
      message,
      severity: NotificationSeverity.INFO,
      ...options,
    });
  }, [addNotification]);
  
  /**
   * Show a warning notification.
   */
  const showWarning = useCallback((message, options = {}) => {
    return addNotification({
      message,
      severity: NotificationSeverity.WARNING,
      autoHideDuration: 8000,
      ...options,
    });
  }, [addNotification]);
  
  /**
   * Show an error notification.
   */
  const showError = useCallback((message, options = {}) => {
    return addNotification({
      message,
      severity: NotificationSeverity.ERROR,
      autoHideDuration: 10000,
      ...options,
    });
  }, [addNotification]);
  
  /**
   * Show an error from an API response.
   * Handles the unified error response format.
   */
  const showApiError = useCallback((apiResponse, options = {}) => {
    // Handle unified error response format
    if (apiResponse?.error) {
      const { error, request_id } = apiResponse;
      return addNotification({
        message: error.user_message || error.message || 'An error occurred',
        title: getErrorTitle(error.severity),
        severity: mapSeverity(error.severity),
        errorCode: error.code,
        requestId: request_id,
        recoveryAction: error.recovery_action,
        details: error.details,
        autoHideDuration: 10000,
        ...options,
      });
    }
    
    // Handle validation error response (multiple errors)
    if (apiResponse?.errors && Array.isArray(apiResponse.errors)) {
      const firstError = apiResponse.errors[0];
      const otherCount = apiResponse.errors.length - 1;
      const message = otherCount > 0 
        ? `${firstError.user_message} (+${otherCount} more)`
        : firstError.user_message;
        
      return addNotification({
        message,
        severity: NotificationSeverity.ERROR,
        errorCode: firstError.code,
        requestId: apiResponse.request_id,
        recoveryAction: RecoveryAction.FAIL_FAST,
        autoHideDuration: 10000,
        ...options,
      });
    }
    
    // Handle plain string errors
    if (typeof apiResponse === 'string') {
      return showError(apiResponse, options);
    }
    
    // Handle generic error objects
    return showError(
      apiResponse?.message || apiResponse?.detail || 'An unexpected error occurred',
      options
    );
  }, [addNotification, showError]);
  
  const contextValue = useMemo(() => ({
    notifications,
    showNotification,
    showSuccess,
    showInfo,
    showWarning,
    showError,
    showApiError,
    removeNotification,
    clearAll,
  }), [
    notifications,
    showNotification,
    showSuccess,
    showInfo,
    showWarning,
    showError,
    showApiError,
    removeNotification,
    clearAll,
  ]);
  
  return (
    <NotificationContext.Provider value={contextValue}>
      {children}
      
      {/* Render notification stack */}
      <Box
        sx={{
          position: 'fixed',
          bottom: 24,
          left: '50%',
          transform: 'translateX(-50%)',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          gap: 1,
        }}
      >
        {notifications.map((notification) => (
          <NotificationItem
            key={notification.id}
            notification={notification}
            onClose={removeNotification}
            onRetry={notification.onRetry}
            position={mergedConfig.position}
          />
        ))}
      </Box>
    </NotificationContext.Provider>
  );
}


/**
 * Hook to access notification context.
 */
export function useNotification() {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
}


/**
 * Helper: Map API severity to MUI Alert severity.
 */
function mapSeverity(apiSeverity) {
  switch (apiSeverity) {
    case 'low':
      return NotificationSeverity.WARNING;
    case 'medium':
      return NotificationSeverity.ERROR;
    case 'high':
    case 'critical':
      return NotificationSeverity.ERROR;
    default:
      return NotificationSeverity.ERROR;
  }
}


/**
 * Helper: Get title based on severity.
 */
function getErrorTitle(severity) {
  switch (severity) {
    case 'low':
      return 'Attention';
    case 'medium':
      return 'Error';
    case 'high':
      return 'Error';
    case 'critical':
      return 'Critical Error';
    default:
      return null;
  }
}


export default NotificationContext;
