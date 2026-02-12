import { useState, useEffect } from 'react';
import {
  Menu,
  MenuItem,
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
import { Link } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import MailIcon from '@mui/icons-material/Mail';
import DraftsIcon from '@mui/icons-material/Drafts';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { formatDistanceToNow } from 'date-fns';
import { useTranslation } from 'react-i18next';

import notificationsApi from '../../services/notificationsApi';
import EmptyState from './EmptyState';

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
function NotificationDropdown({ anchorEl, open, onClose, onMarkAllRead, onCountChange }) {
  const { t } = useTranslation('common');
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (open) {
      loadNotifications();
    }
  }, [open]);

  const loadNotifications = async () => {
    setLoading(true);
    try {
      const data = await notificationsApi.listNotifications({ limit: 10 });
      setNotifications(Array.isArray(data) ? data : data.notifications || []);
    } catch (err) {
      console.error('Failed to load notifications:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleMarkAsRead = async (notificationId) => {
    try {
      await notificationsApi.markAsRead(notificationId);
      setNotifications(prev => 
        prev.map(n => n.id === notificationId ? { ...n, read: true } : n)
      );
      // Update unread count
      const unreadCount = notifications.filter(n => !n.read && n.id !== notificationId).length;
      onCountChange?.(unreadCount);
    } catch (err) {
      console.error('Failed to mark notification as read:', err);
    }
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

      {/* Content */}
      {loading ? (
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
                      {notification.message}
                    </Typography>
                    <Typography variant="caption" color="text.disabled" sx={{ mt: 0.5, display: 'block' }}>
                      {formatDistanceToNow(new Date(notification.created_at), { addSuffix: true })}
                    </Typography>
                  </>
                }
              />
              {notification.link && (
                <IconButton
                  size="small"
                  component={Link}
                  to={notification.link}
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

export default NotificationDropdown;
