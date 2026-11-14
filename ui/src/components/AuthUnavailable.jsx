import { Alert, Box, Button, CircularProgress, Container, Typography } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useTranslation } from 'react-i18next';

// Never display raw response bodies here: a proxy/configuration error may be
// HTML or contain deployment details. Authentication remains unconfirmed.
export default function AuthUnavailable({ error, onRetry, isRetrying = false }) {
  const { t } = useTranslation('common');
  const explanations = {
    AUTH_NETWORK: t('login.unavailable.network', {
      defaultValue: 'We could not reach the sign-in service. Check your connection and retry.',
    }),
    AUTH_TIMEOUT: t('login.unavailable.timeout', {
      defaultValue: 'The sign-in service took too long to respond. Retry in a moment.',
    }),
    AUTH_CONFIGURATION: t('login.unavailable.configuration', {
      defaultValue: 'The sign-in service could not check your session. If retrying does not help, contact the operator of this environment.',
    }),
    AUTH_RESPONSE_INVALID: t('login.unavailable.configuration', {
      defaultValue: 'The sign-in service could not check your session. If retrying does not help, contact the operator of this environment.',
    }),
  };
  const message = explanations[error?.code] || t('login.unavailable.service', {
    defaultValue: 'The sign-in service is temporarily unavailable. Retry in a moment.',
  });

  return (
    <Container maxWidth="sm" sx={{ py: 6 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        {t('login.unavailable.title', { defaultValue: 'Sign-in is temporarily unavailable' })}
      </Typography>
      <Alert severity="error" sx={{ my: 3 }}>{message}</Alert>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        {t('login.unavailable.intent', {
          defaultValue: 'We could not confirm your session. Your requested destination is kept while you retry.',
        })}
      </Typography>
      <Box aria-busy={isRetrying}>
        <Button
          variant="contained"
          disabled={isRetrying}
          onClick={() => onRetry()}
          startIcon={isRetrying ? <CircularProgress size={18} color="inherit" aria-hidden="true" /> : <RefreshIcon />}
        >
          {isRetrying
            ? t('login.unavailable.retrying', { defaultValue: 'Checking sign-in…' })
            : t('login.unavailable.retry', { defaultValue: 'Retry sign-in check' })}
        </Button>
      </Box>
    </Container>
  );
}
