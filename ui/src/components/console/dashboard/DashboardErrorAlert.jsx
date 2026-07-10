import { Alert, AlertTitle, Button, Typography } from '@mui/material';

function resolveMessageId(error) {
  return error?.messageId
    || error?.message_id
    || error?.requestId
    || error?.response?.message_id
    || error?.response?.data?.message_id
    || error?.details?.message_id
    || null;
}

function toRenderableMessage(value) {
  if (value == null) {
    return null;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed || null;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  if (value instanceof Error) {
    return toRenderableMessage(value.message);
  }

  if (Array.isArray(value)) {
    const messages = value
      .map((item) => toRenderableMessage(item))
      .filter(Boolean);
    return messages.length ? messages.join('; ') : null;
  }

  if (typeof value === 'object') {
    return toRenderableMessage(value.user_message)
      || toRenderableMessage(value.message)
      || toRenderableMessage(value.error_description)
      || toRenderableMessage(value.detail)
      || toRenderableMessage(value.description)
      || toRenderableMessage(value.error);
  }

  return null;
}

function resolveMessage(error, fallback) {
  const candidates = [
    error?.error_description,
    error?.response?.error_description,
    error?.response?.data?.error_description,
    error?.response?.data?.detail,
    error?.details,
    error?.message,
    fallback,
  ];

  for (const candidate of candidates) {
    const message = toRenderableMessage(candidate);
    if (message) {
      return message;
    }
  }

  return 'This dashboard section is temporarily unavailable.';
}

export default function DashboardErrorAlert({ title, error, onRetry, fallback }) {
  const messageId = resolveMessageId(error);
  const message = resolveMessage(error, fallback || 'This dashboard section is temporarily unavailable.');

  return (
    <Alert
      severity="warning"
      action={onRetry ? (
        <Button color="inherit" size="small" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    >
      <AlertTitle>{title || 'Dashboard data unavailable'}</AlertTitle>
      <Typography variant="body2">{message}</Typography>
      {messageId ? (
        <Typography variant="caption" sx={{ display: 'block', mt: 0.75 }}>
          Message ID: {messageId}
        </Typography>
      ) : null}
    </Alert>
  );
}
