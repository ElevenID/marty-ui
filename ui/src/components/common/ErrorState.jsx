import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Paper,
  Alert,
  Collapse,
  IconButton,
  Stack,
  Chip,
} from '@mui/material';
import {
  ErrorOutline as ErrorIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  ContentCopy as CopyIcon,
  Support as SupportIcon,
} from '@mui/icons-material';
import { useTranslation } from 'react-i18next';
import { useNotifications } from '../../hooks/useNotifications';

/**
 * ErrorState - Standardized error display component
 * 
 * @param {Error|Object} error - Error object or error details
 * @param {Function} onRetry - Optional retry callback
 * @param {string} title - Custom error title
 * @param {string} message - User-friendly error message
 * @param {boolean} showTechnicalDetails - Whether to show technical details (default: true)
 * @param {boolean} showSupport - Whether to show support contact (default: true)
 * @param {string} variant - Display variant: 'full' | 'inline' | 'compact'
 */
export default function ErrorState({
  error,
  onRetry,
  title,
  message,
  showTechnicalDetails = true,
  showSupport = true,
  variant = 'full',
}) {
  const [expanded, setExpanded] = useState(false);
  const { t } = useTranslation('errors');
  const { showNotification } = useNotifications();

  // Parse error details
  const errorDetails = React.useMemo(() => {
    if (!error) {
      return {
        title: title || t('errorState.defaultTitle'),
        userMessage: message || t('errorState.unexpectedError'),
        technicalMessage: null,
        code: null,
        requestId: null,
        timestamp: new Date().toISOString(),
        severity: 'high',
      };
    }

    // Handle structured API error
    if (error.error) {
      return {
        title: title || t('errorState.operationFailed'),
        userMessage: error.error.user_message || message || t('errorState.genericError'),
        technicalMessage: error.error.message,
        code: error.error.code,
        requestId: error.request_id,
        timestamp: error.timestamp || new Date().toISOString(),
        severity: error.error.severity || 'high',
      };
    }

    // Handle standard Error object
    return {
      title: title || t('errorState.error'),
      userMessage: message || error.message || t('errorState.unexpectedError'),
      technicalMessage: error.message,
      code: error.code || error.name,
      requestId: error.requestId,
      timestamp: error.timestamp || new Date().toISOString(),
      severity: 'high',
    };
  }, [error, title, message, t]);

  const handleCopyDetails = () => {
    const details = JSON.stringify({
      title: errorDetails.title,
      message: errorDetails.userMessage,
      technical: errorDetails.technicalMessage,
      code: errorDetails.code,
      requestId: errorDetails.requestId,
      timestamp: errorDetails.timestamp,
    }, null, 2);

    navigator.clipboard.writeText(details);
    showNotification?.(t('errorState.detailsCopied'), 'info');
  };

  const handleContactSupport = () => {
    const subject = encodeURIComponent(t('errorState.errorReport', { code: errorDetails.code || 'Unknown' }));
    const body = encodeURIComponent(
      `${t('errorState.requestId')} ${errorDetails.requestId || t('errorState.notAvailable')}\n` +
      `${t('errorState.timestamp')} ${errorDetails.timestamp}\n` +
      `${t('errorState.errorCode')} ${errorDetails.code || t('errorState.notAvailable')}\n` +
      `${t('errorState.message')} ${errorDetails.userMessage}\n\n` +
      `${t('errorState.technicalDetails')}\n${errorDetails.technicalMessage || t('errorState.notAvailable')}`
    );
    window.location.href = `mailto:support@example.com?subject=${subject}&body=${body}`;
  };

  // Compact variant
  if (variant === 'compact') {
    return (
      <Alert 
        severity="error" 
        action={
          onRetry && (
            <Button color="inherit" size="small" onClick={onRetry}>
              {t('errorState.retry')}
            </Button>
          )
        }
      >
        {errorDetails.userMessage}
      </Alert>
    );
  }

  // Inline variant
  if (variant === 'inline') {
    return (
      <Box sx={{ py: 2 }}>
        <Alert 
          severity="error"
          action={
            <Stack direction="row" spacing={1}>
              {onRetry && (
                <IconButton color="inherit" size="small" onClick={onRetry}>
                  <RefreshIcon fontSize="small" />
                </IconButton>
              )}
              {showTechnicalDetails && (
                <IconButton 
                  color="inherit" 
                  size="small" 
                  onClick={() => setExpanded(!expanded)}
                >
                  <ExpandMoreIcon 
                    fontSize="small"
                    sx={{
                      transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.3s',
                    }}
                  />
                </IconButton>
              )}
            </Stack>
          }
        >
          <Typography variant="body2">{errorDetails.userMessage}</Typography>
          
          <Collapse in={expanded} timeout="auto">
            <Box sx={{ mt: 2, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
              <Typography variant="caption" display="block" gutterBottom>
                <strong>{t('errorState.errorCode')}</strong> {errorDetails.code || t('errorState.notAvailable')}
              </Typography>
              {errorDetails.requestId && (
                <Typography variant="caption" display="block" gutterBottom>
                  <strong>{t('errorState.requestId')}</strong> {errorDetails.requestId}
                </Typography>
              )}
              {errorDetails.technicalMessage && (
                <Typography variant="caption" display="block" gutterBottom>
                  <strong>{t('errorState.technicalDetails')}</strong> {errorDetails.technicalMessage}
                </Typography>
              )}
            </Box>
          </Collapse>
        </Alert>
      </Box>
    );
  }

  // Full page variant (default)
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '400px',
        p: 3,
      }}
    >
      <Paper
        elevation={2}
        sx={{
          p: 4,
          maxWidth: 600,
          width: '100%',
          textAlign: 'center',
        }}
      >
        <ErrorIcon
          sx={{
            fontSize: 64,
            color: 'error.main',
            mb: 2,
          }}
        />

        <Typography variant="h5" gutterBottom color="error">
          {errorDetails.title}
        </Typography>

        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          {errorDetails.userMessage}
        </Typography>

        {/* Metadata chips */}
        <Stack 
          direction="row" 
          spacing={1} 
          justifyContent="center" 
          sx={{ mb: 3 }}
        >
          {errorDetails.code && (
            <Chip 
              label={`Code: ${errorDetails.code}`} 
              size="small" 
              variant="outlined" 
            />
          )}
          {errorDetails.requestId && (
            <Chip 
              label={`ID: ${errorDetails.requestId.slice(0, 8)}`} 
              size="small" 
              variant="outlined" 
            />
          )}
        </Stack>

        {/* Action buttons */}
        <Stack direction="row" spacing={2} justifyContent="center" sx={{ mb: 3 }}>
          {onRetry && (
            <Button
              variant="contained"
              startIcon={<RefreshIcon />}
              onClick={onRetry}
            >
              {t('errorState.retry')}
            </Button>
          )}
          {showSupport && (
            <Button
              variant="outlined"
              startIcon={<SupportIcon />}
              onClick={handleContactSupport}
            >
              {t('errorState.contactSupport')}
            </Button>
          )}
        </Stack>

        {/* Technical details section */}
        {showTechnicalDetails && (errorDetails.technicalMessage || errorDetails.requestId) && (
          <Box sx={{ mt: 3 }}>
            <Button
              size="small"
              endIcon={
                <ExpandMoreIcon
                  sx={{
                    transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'transform 0.3s',
                  }}
                />
              }
              onClick={() => setExpanded(!expanded)}
            >
              {t('errorState.showTechnicalDetails')}
            </Button>

            <Collapse in={expanded} timeout="auto">
              <Paper
                variant="outlined"
                sx={{
                  mt: 2,
                  p: 2,
                  bgcolor: 'grey.50',
                  textAlign: 'left',
                }}
              >
                {errorDetails.code && (
                  <Typography variant="body2" gutterBottom>
                    <strong>{t('errorState.errorCode')}</strong> {errorDetails.code}
                  </Typography>
                )}
                {errorDetails.requestId && (
                  <Typography variant="body2" gutterBottom>
                    <strong>{t('errorState.requestId')}</strong> {errorDetails.requestId}
                  </Typography>
                )}
                {errorDetails.timestamp && (
                  <Typography variant="body2" gutterBottom>
                    <strong>{t('errorState.timestamp')}</strong> {new Date(errorDetails.timestamp).toLocaleString()}
                  </Typography>
                )}
                {errorDetails.technicalMessage && (
                  <Typography variant="body2" gutterBottom>
                    <strong>{t('errorState.technicalMessage')}</strong> {errorDetails.technicalMessage}
                  </Typography>
                )}

                <Button
                  size="small"
                  startIcon={<CopyIcon />}
                  onClick={handleCopyDetails}
                  sx={{ mt: 2 }}
                >
                  {t('errorState.copyDetails')}
                </Button>
              </Paper>
            </Collapse>
          </Box>
        )}
      </Paper>
    </Box>
  );
}
