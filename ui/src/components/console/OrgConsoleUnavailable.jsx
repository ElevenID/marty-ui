import { Alert, Box, Button, Container, Stack, Typography } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';

function resolveMessage(error) {
  return error?.message || 'We could not load your organization memberships.';
}

function resolveMessageId(error) {
  return error?.messageId
    || error?.message_id
    || error?.response?.message_id
    || error?.response?.request_id
    || error?.requestId
    || null;
}

export default function OrgConsoleUnavailable({ error, onRetry }) {
  const messageId = resolveMessageId(error);

  return (
    <Container maxWidth="md" sx={{ py: 6 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom fontWeight={600}>
          Organization console unavailable
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Marty could not confirm your organization memberships. Your account is signed in, but org-scoped setup is paused until the organization service responds.
        </Typography>
      </Box>

      <Alert severity="error" sx={{ mb: 3 }}>
        <Stack spacing={1}>
          <Typography variant="body2">{resolveMessage(error)}</Typography>
          {messageId && (
            <Typography variant="caption" fontFamily="monospace">
              Message ID: {messageId}
            </Typography>
          )}
        </Stack>
      </Alert>

      <Button
        variant="contained"
        startIcon={<RefreshIcon />}
        onClick={onRetry}
      >
        Retry
      </Button>
    </Container>
  );
}
