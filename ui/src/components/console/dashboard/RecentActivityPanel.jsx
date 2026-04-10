/**
 * Recent Activity Panel
 * 
 * Displays the last 5 audit events on the dashboard.
 * Provides quick visibility into recent system activity.
 */

import { useEffect, useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
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
  Skeleton,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import BadgeIcon from '@mui/icons-material/Badge';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import PersonIcon from '@mui/icons-material/Person';

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { listAuditEvents } from '../../../services/auditApi';
import sseService, { EVENT_TYPES } from '../../../services/sseService';

/**
 * Severity levels and their visual styling factory
 */
const getSeverityConfig = (t) => ({
  info: {
    color: 'info',
    icon: InfoIcon,
    label: t('dashboard.recentActivity.info'),
  },
  success: {
    color: 'success',
    icon: CheckCircleIcon,
    label: t('dashboard.recentActivity.success'),
  },
  warning: {
    color: 'warning',
    icon: WarningIcon,
    label: t('dashboard.recentActivity.warning'),
  },
  error: {
    color: 'error',
    icon: ErrorIcon,
    label: t('dashboard.recentActivity.error'),
  },
});

/**
 * Event type to icon mapping
 */
const EVENT_ICONS = {
  credential: BadgeIcon,
  flow: AccountTreeIcon,
  trust: VerifiedUserIcon,
  user: PersonIcon,
  default: InfoIcon,
};

/**
 * Format relative time
 */
function formatRelativeTime(dateString, t) {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now - date;
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMinutes < 1) return t('dashboard.recentActivity.justNow');
  if (diffMinutes < 60) return t('dashboard.recentActivity.minutesAgo', { minutes: diffMinutes });
  if (diffHours < 24) return t('dashboard.recentActivity.hoursAgo', { hours: diffHours });
  if (diffDays < 7) return t('dashboard.recentActivity.daysAgo', { days: diffDays });
  return date.toLocaleDateString();
}

/**
 * Get severity from event type/action
 */
function getSeverity(event) {
  if (event.severity) return event.severity;
  if (event.action?.includes('failed') || event.action?.includes('error')) return 'error';
  if (event.action?.includes('warning') || event.action?.includes('rejected')) return 'warning';
  if (event.action?.includes('success') || event.action?.includes('completed') || event.action?.includes('issued')) return 'success';
  return 'info';
}

/**
 * Get category from event
 */
function getCategory(event) {
  if (event.category) return event.category;
  if (event.action?.includes('credential')) return 'credential';
  if (event.action?.includes('flow')) return 'flow';
  if (event.action?.includes('trust')) return 'trust';
  if (event.action?.includes('user') || event.action?.includes('login')) return 'user';
  return 'default';
}

/**
 * Activity Row Component
 */
function ActivityRow({ event }) {
  const { t } = useTranslation('console');
  const SEVERITY_CONFIG = getSeverityConfig(t);
  const severity = getSeverity(event);
  const category = getCategory(event);
  const SeverityIcon = SEVERITY_CONFIG[severity]?.icon || InfoIcon;
  const CategoryIcon = EVENT_ICONS[category] || EVENT_ICONS.default;

  const getResourceLink = () => {
    if (event.resource_type === 'credential') return `/console/operate/issuance/${event.resource_id}`;
    if (event.resource_type === 'flow') return `/console/operate/flow-instances/${event.resource_id}`;
    if (event.resource_type === 'application') return `/console/operate/applications/${event.resource_id}`;
    return null;
  };

  const resourceLink = getResourceLink();

  return (
    <ListItem
      disablePadding
      sx={{ py: 1 }}
      secondaryAction={
        <Chip
          size="small"
          label={SEVERITY_CONFIG[severity]?.label || 'Info'}
          color={SEVERITY_CONFIG[severity]?.color || 'default'}
          variant="outlined"
        />
      }
    >
      <ListItemIcon sx={{ minWidth: 36 }}>
        <SeverityIcon
          fontSize="small"
          color={SEVERITY_CONFIG[severity]?.color || 'action'}
        />
      </ListItemIcon>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <CategoryIcon fontSize="small" color="action" />
            <Typography variant="body2" component="span">
              {event.action?.replace(/_/g, ' ').replace(/\./g, ' ') || t('dashboard.recentActivity.unknownAction')}
            </Typography>
            {resourceLink && (
              <Button
                size="small"
                component={Link}
                to={resourceLink}
                sx={{ ml: 1, minWidth: 'auto', p: 0.25 }}
              >
                {t('dashboard.recentActivity.view')}
              </Button>
            )}
          </Box>
        }
        secondary={
          <Typography variant="caption" color="text.secondary">
            {event.actor || t('dashboard.recentActivity.system')} • {formatRelativeTime(event.timestamp, t)}
          </Typography>
        }
      />
    </ListItem>
  );
}

/**
 * Recent Activity Panel Component
 */
export function RecentActivityPanel() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrgId = activeOrgId || organizationId;
  const [liveEvents, setLiveEvents] = useState([]);
  const { data: fetchedEvents = [], loading } = useAsyncData(
    async () => {
      if (!effectiveOrgId) return [];
      try {
        const response = await listAuditEvents(effectiveOrgId, { limit: 5 });
        return response?.events || response || [];
      } catch (err) {
        console.error('Failed to fetch recent activity:', err);
        return [];
      }
    },
    [effectiveOrgId]
  );

  // Merge live SSE events with fetched events, newest first, capped at 10
  const events = [...liveEvents, ...(fetchedEvents || [])]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 10);

  // Subscribe to SSE for live event updates
  useEffect(() => {
    if (!effectiveOrgId) return;

    const liveEventTypes = [
      EVENT_TYPES.CREDENTIAL_ISSUED,
      EVENT_TYPES.CREDENTIAL_REVOKED,
      EVENT_TYPES.APPLICATION_SUBMITTED,
      EVENT_TYPES.APPLICATION_APPROVED,
      EVENT_TYPES.APPLICATION_REJECTED,
      EVENT_TYPES.FLOW_EXECUTION_COMPLETED,
      EVENT_TYPES.FLOW_EXECUTION_FAILED,
      EVENT_TYPES.VERIFICATION_COMPLETED,
    ];

    const unsubscribers = liveEventTypes.map((eventType) =>
      sseService.on(eventType, (data) => {
        const newEvent = {
          id: data.id || `sse-${Date.now()}`,
          timestamp: data.timestamp || new Date().toISOString(),
          action: eventType,
          actor: data.actor || data.user_email || '',
          resource_type: data.resource_type || eventType.split('.')[0],
          resource_id: data.resource_id || '',
          severity: data.severity || getSeverity({ action: eventType }),
        };
        setLiveEvents((prev) => [newEvent, ...prev].slice(0, 10));
      })
    );

    return () => unsubscribers.forEach((unsub) => unsub());
  }, [effectiveOrgId]);

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Typography variant="h6">
          {t('dashboard.recentActivity.title')}
        </Typography>
        <Button
          size="small"
          component={Link}
          to="/console/audit"
          endIcon={<ArrowForwardIcon />}
        >
          {t('dashboard.recentActivity.viewAll')}
        </Button>
      </Box>

      {loading ? (
        <Box>
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} height={48} sx={{ my: 0.5 }} />
          ))}
        </Box>
      ) : events.length === 0 ? (
        <Box sx={{ py: 3, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            {t('dashboard.recentActivity.noActivity')}
          </Typography>
        </Box>
      ) : (
        <List disablePadding>
          {events.map((event) => (
            <ActivityRow key={event.id} event={event} />
          ))}
        </List>
      )}
    </Paper>
  );
}
