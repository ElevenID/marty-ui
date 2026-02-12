import { useState, useEffect } from 'react';
import {
  IconButton,
  Badge,
  Tooltip,
} from '@mui/material';
import NotificationsIcon from '@mui/icons-material/Notifications';
import NotificationsNoneIcon from '@mui/icons-material/NotificationsNone';
import { useTranslation } from 'react-i18next';

import notificationsApi from '../../services/notificationsApi';
import NotificationDropdown from './NotificationDropdown';

/**
 * NotificationBell - Bell icon with unread count badge
 * 
 * Displays a bell icon in the header that shows unread notification count.
 * Clicking opens a dropdown with recent notifications.
 * Automatically polls for new notifications.
 * 
 * @example
 * <NotificationBell />
 */
function NotificationBell() {
  const { t } = useTranslation('common');
  const [unreadCount, setUnreadCount] = useState(0);
  const [anchorEl, setAnchorEl] = useState(null);
  const [polling, setPolling] = useState(true);

  useEffect(() => {
    loadUnreadCount();

    // Poll every 30 seconds for new notifications
    const interval = setInterval(() => {
      if (polling) {
        loadUnreadCount();
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [polling]);

  const loadUnreadCount = async () => {
    try {
      const count = await notificationsApi.getUnreadCount();
      setUnreadCount(count);
    } catch (err) {
      console.error('Failed to load unread count:', err);
    }
  };

  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
    loadUnreadCount(); // Refresh count after closing
  };

  const handleMarkAllRead = async () => {
    try {
      await notificationsApi.markAllAsRead();
      setUnreadCount(0);
      loadUnreadCount();
    } catch (err) {
      console.error('Failed to mark all as read:', err);
    }
  };

  const open = Boolean(anchorEl);

  return (
    <>
      <Tooltip title={unreadCount > 0 ? t('notifications.unreadCount', { count: unreadCount }) : t('notifications.title')}>
        <IconButton
          onClick={handleClick}
          size="small"
          sx={{ color: 'white' }}
          aria-label={t('notifications.title').toLowerCase()}
          aria-controls={open ? 'notification-dropdown' : undefined}
          aria-haspopup="true"
          aria-expanded={open ? 'true' : undefined}
        >
          <Badge 
            badgeContent={unreadCount} 
            color="error"
            max={99}
          >
            {unreadCount > 0 ? <NotificationsIcon /> : <NotificationsNoneIcon />}
          </Badge>
        </IconButton>
      </Tooltip>

      <NotificationDropdown
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        onMarkAllRead={handleMarkAllRead}
        onCountChange={setUnreadCount}
      />
    </>
  );
}

export default NotificationBell;
