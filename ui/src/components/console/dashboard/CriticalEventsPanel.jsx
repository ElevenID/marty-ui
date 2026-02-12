/**
 * Critical Events Panel
 * 
 * Shows critical signals (not just passive activity):
 * - Failed flows
 * - Revocations
 * - Auth failures
 * - Webhook failures
 * 
 * Filtered to last 24 hours only
 * Purpose: immediate visibility into system problems
 */

import {
  Box,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Button,
  Alert,
  Skeleton,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import ErrorIcon from '@mui/icons-material/Error';
import BlockIcon from '@mui/icons-material/Block';
import WebhookIcon from '@mui/icons-material/Webhook';
import LockIcon from '@mui/icons-material/Lock';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

/**
 * Event type configuration factory
 */
const getEventConfig = (t) => ({
  flow_failed: {
    icon: AccountTreeIcon,
    color: 'error',
    label: t('dashboard.criticalEvents.flowFailed'),
  },
  revocation: {
    icon: BlockIcon,
    color: 'warning',
    label: t('dashboard.criticalEvents.revocation'),
  },
  auth_failure: {
    icon: LockIcon,
    color: 'error',
    label: t('dashboard.criticalEvents.authFailure'),
  },
  webhook_failure: {
    icon: WebhookIcon,
    color: 'error',
    label: t('dashboard.criticalEvents.webhookFailure'),
  },
});

/**
 * Format relative time
 */
function formatRelativeTime(dateString, t) {
  if (!dateString) return '';
  
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now - date;
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);

  if (diffMinutes < 1) return t('dashboard.criticalEvents.justNow');
  if (diffMinutes < 60) return t('dashboard.criticalEvents.minutesAgo', { minutes: diffMinutes });
  if (diffHours < 24) return t('dashboard.criticalEvents.hoursAgo', { hours: diffHours });
  return date.toLocaleTimeString();
}

/**
 * Critical event item
 */
function CriticalEventItem({ event }) {
  const { t } = useTranslation('console');
  const EVENT_CONFIG = getEventConfig(t);
  const config = EVENT_CONFIG[event.type] || {
    icon: ErrorIcon,
    color: 'error',
    label: t('dashboard.criticalEvents.error'),
  };
  
  const Icon = config.icon;

  return (
    <ListItem
      sx={{
        py: 1.5,
        borderBottom: '1px solid',
        borderColor: 'divider',
        '&:last-child': { borderBottom: 'none' },
      }}
    >
      <ListItemIcon>
        <Icon color={config.color} />
      </ListItemIcon>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" fontWeight={500}>
              {event.title || event.message}
            </Typography>
            <Chip
              label={config.label}
              size="small"
              color={config.color}
              sx={{ height: 20, fontSize: '0.65rem' }}
            />
          </Box>
        }
        secondary={
          <Box sx={{ display: 'flex', gap: 2, mt: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              {formatRelativeTime(event.timestamp, t)}
            </Typography>
            {event.details && (
              <Typography variant="caption" color="text.secondary">
                {event.details}
              </Typography>
            )}
          </Box>
        }
      />
    </ListItem>
  );
}

/**
 * Critical Events Panel Component
 */
export function CriticalEventsPanel({ events, loading = false }) {
  const { t } = useTranslation('console');
  
  // Filter to critical events only (last 24h)
  const now = new Date();
  const twentyFourHoursAgo = new Date(now - 24 * 60 * 60 * 1000);
  
  const criticalEvents = (events || [])
    .filter(event => {
      if (!event.timestamp) return false;
      const eventDate = new Date(event.timestamp);
      return eventDate >= twentyFourHoursAgo;
    })
    .filter(event => 
      event.severity === 'error' || 
      event.severity === 'warning' ||
      event.type?.includes('failed') ||
      event.type?.includes('failure') ||
      event.type?.includes('revocation') ||
      event.type?.includes('auth')
    )
    .slice(0, 10); // Max 10 events

  if (loading) {
    return (
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('dashboard.criticalEvents.title')}
        </Typography>
        <Box sx={{ py: 2 }}>
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} height={60} sx={{ mb: 1 }} />
          ))}
        </Box>
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Box>
          <Typography variant="h6">
            {t('dashboard.criticalEvents.title')}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {t('dashboard.criticalEvents.description')}
          </Typography>
        </Box>
        <Button
          component={Link}
          to="/console/audit"
          size="small"
          endIcon={<ArrowForwardIcon />}
        >
          {t('dashboard.criticalEvents.viewAll')}
        </Button>
      </Box>

      {criticalEvents.length === 0 ? (
        <Alert severity="success" icon={<CheckCircleIcon />}>
          <Typography variant="body2">
            {t('dashboard.criticalEvents.noCriticalEvents')}
          </Typography>
        </Alert>
      ) : (
        <>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2">
              {t('dashboard.criticalEvents.criticalEventsDetected', { count: criticalEvents.length })}
            </Typography>
          </Alert>
          
          <List sx={{ p: 0 }}>
            {criticalEvents.map((event, idx) => (
              <CriticalEventItem key={event.id || idx} event={event} />
            ))}
          </List>
        </>
      )}
    </Paper>
  );
}
