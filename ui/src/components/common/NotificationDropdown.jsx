import { useState, useEffect, useRef } from 'react';
import {
  Menu,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Typography,
  Box,
  Button,
  Divider,
  IconButton,
  Chip,
  CircularProgress,
} from '@mui/material';
import { Link } from 'react-router';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import MailIcon from '@mui/icons-material/Mail';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { formatDistanceToNow } from 'date-fns';
import { useTranslation } from 'react-i18next';

import notificationsApi from '../../services/notificationsApi';
import EmptyState from './EmptyState';

const isConsoleLink = (value) => typeof value === 'string' && /^\/console(?:\/|$)/.test(value)
  && !value.includes('\\') && [...value].every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127);

/**
 * NotificationDropdown - Dropdown menu showing recent notifications
 * 
 * Displays the 10 most recent notifications in a dropdown menu.
 * Users can mark individual notifications as read or view all notifications.
 * 
 * @param {Object} anchorEl - Menu anchor element
 * @param {boolean} open - Whether the menu is open
 * @param {function} onClose - Close callback
 * @param {function} onMarkAllRead - Mark all as read callback
 * @param {function} onCountChange - Callback when unread count changes
 */
function ScopedNotificationDropdown({ organizationId, recipientId, anchorEl, open, onClose, onMarkAllRead, onCountChange }) {
  const { t } = useTranslation('common');
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    let current = true;
    if (!open) return () => { current = false; };
    setLoading(true); setError(''); setNotifications([]);
    notificationsApi.listNotifications({ organization_id: organizationId, recipient_id: recipientId, limit: 10 }).then((data) => {
      if (current) setNotifications(data);
    }).catch((failure) => { if (current) setError(failure?.message || 'Notifications could not be loaded.'); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [open, organizationId, recipientId, attempt]);
  const handleMarkAsRead = async (notificationId) => {
    try {
      await notificationsApi.markAsRead(notificationId, organizationId);
      if (!mounted.current) return;
      setAttempt((value) => value + 1);
      onCountChange?.();
    } catch (failure) { if (mounted.current) setError(failure?.message || 'Notification could not be updated.'); }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'error':
        return <ErrorIcon color="error" fontSize="small" />;
      case 'warning':
        return <WarningIcon color="warning" fontSize="small" />;
      case 'success':
        return <CheckCircleIcon color="success" fontSize="small" />;
      default:
        return <InfoIcon color="info" fontSize="small" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'error':
        return 'error.light';
      case 'warning':
        return 'warning.light';
      case 'success':
        return 'success.light';
      default:
        return 'info.light';
    }
  };

  return (
    <Menu
      id="notification-dropdown"
      anchorEl={anchorEl}
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: 400,
          maxHeight: 600,
        },
      }}
      transformOrigin={{ horizontal: 'right', vertical: 'top' }}
      anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
    >
      {/* Header */}
      <Box sx={{ px: 2, py: 1.5, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h6">{t('notifications.title')}</Typography>
        {notifications.some(n => !n.read) && (
          <Button size="small" onClick={onMarkAllRead}>
            {t('notifications.markAllRead')}
          </Button>
        )}
      </Box>
      <Divider />

      {error && <Box sx={{ p: 2 }}><Typography color="error">{error}</Typography><Button onClick={() => setAttempt((value) => value + 1)}>Retry notifications</Button></Box>}
      {/* Content */}
      {error ? null : loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      ) : notifications.length === 0 ? (
        <Box sx={{ py: 3, px: 2 }}>
          <EmptyState
            icon={MailIcon}
            title={t('notifications.empty.title')}
            description={t('notifications.empty.description')}
          />
        </Box>
      ) : (
        <List sx={{ py: 0, maxHeight: 400, overflow: 'auto' }}>
          {notifications.map((notification) => (
            <ListItem
              key={notification.id}
              sx={{
                borderLeft: 4,
                borderColor: notification.read ? 'transparent' : getSeverityColor(notification.severity),
                bgcolor: notification.read ? 'transparent' : 'action.hover',
                '&:hover': { bgcolor: 'action.selected' },
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'flex-start',
              }}
              onClick={() => !notification.read && handleMarkAsRead(notification.id)}
            >
              <ListItemIcon sx={{ minWidth: 40, mt: 0.5 }}>
                {getSeverityIcon(notification.severity)}
              </ListItemIcon>
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <Typography variant="body2" sx={{ fontWeight: notification.read ? 400 : 600, flex: 1 }}>
                      {notification.title}
                    </Typography>
                    {!notification.read && (
                      <Chip label={t('notifications.newBadge')} size="small" color="primary" sx={{ ml: 1, height: 20 }} />
                    )}
                  </Box>
                }
                secondary={
                  <>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                      {notification.body}
                    </Typography>
                    <Typography variant="caption" color="text.disabled" sx={{ mt: 0.5, display: 'block' }}>
                      {formatDistanceToNow(new Date(notification.created_at), { addSuffix: true })}
                    </Typography>
                  </>
                }
              />
              {isConsoleLink(notification.link) && (
                <IconButton
                  size="small"
                  component={Link}
                  to={notification.link}
                  aria-label="Open notification"
                  onClick={(e) => {
                    e.stopPropagation();
                    onClose();
                  }}
                  sx={{ ml: 1 }}
                >
                  <OpenInNewIcon fontSize="small" />
                </IconButton>
              )}
            </ListItem>
          ))}
        </List>
      )}

      {/* Footer */}
      {notifications.length > 0 && (
        <>
          <Divider />
          <Box sx={{ p: 1, textAlign: 'center' }}>
            <Button
              component={Link}
              to="/console/org/notifications"
              onClick={onClose}
              size="small"
              fullWidth
            >
              {t('notifications.viewAll')}
            </Button>
          </Box>
        </>
      )}
    </Menu>
  );
}

export default function NotificationDropdown(props) {
  if (!props.organizationId || !props.recipientId) return null;
  return <ScopedNotificationDropdown key={`${props.organizationId}:${props.recipientId}`} {...props} />;
}
