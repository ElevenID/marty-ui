import { useCallback, useEffect, useRef, useState } from 'react';
import { IconButton, Badge, Tooltip } from '@mui/material';
import NotificationsIcon from '@mui/icons-material/Notifications';
import NotificationsNoneIcon from '@mui/icons-material/NotificationsNone';
import { useTranslation } from 'react-i18next';
import notificationsApi from '../../services/notificationsApi';
import { useConsole } from '../../contexts/ConsoleContext';
import { useAuth } from '../../hooks/useAuth';
import { usePermissions } from '../../hooks/usePermissions';
import NotificationDropdown from './NotificationDropdown';

function ScopedNotificationBell({ organizationId, recipientId }) {
  const { t } = useTranslation('common');
  const [unreadCount, setUnreadCount] = useState(0);
  const [anchorEl, setAnchorEl] = useState(null);
  const mounted = useRef(false);
  const generation = useRef(0);
  const loadUnreadCount = useCallback(async () => {
    const request = ++generation.current;
    try {
      const result = await notificationsApi.getUnreadCount(organizationId, recipientId);
      if (!Number.isInteger(result?.count) || result.count < 0) throw new Error('Notification count is invalid.');
      if (mounted.current && request === generation.current) setUnreadCount(result.count);
    } catch (error) {
      if (mounted.current && request === generation.current) console.error('Failed to load unread count:', error);
    }
  }, [organizationId, recipientId]);
  useEffect(() => {
    mounted.current = true; loadUnreadCount();
    const interval = setInterval(loadUnreadCount, 30000);
    return () => { mounted.current = false; clearInterval(interval); };
  }, [loadUnreadCount]);
  const handleClose = () => { setAnchorEl(null); loadUnreadCount(); };
  const handleMarkAllRead = async () => {
    try {
      await notificationsApi.markAllAsRead(organizationId, recipientId);
      if (!mounted.current) return;
      setUnreadCount(0); loadUnreadCount();
    } catch (error) { if (mounted.current) console.error('Failed to mark all as read:', error); }
  };
  const open = Boolean(anchorEl);
  return <>
    <Tooltip title={unreadCount > 0 ? t('notifications.unreadCount', { count: unreadCount }) : t('notifications.title')}>
      <IconButton onClick={(event) => setAnchorEl(event.currentTarget)} size="small" sx={{ color: 'white' }}
        aria-label={t('notifications.title').toLowerCase()} aria-controls={open ? 'notification-dropdown' : undefined}
        aria-haspopup="true" aria-expanded={open ? 'true' : undefined}>
        <Badge badgeContent={unreadCount} color="error" max={99}>{unreadCount > 0 ? <NotificationsIcon /> : <NotificationsNoneIcon />}</Badge>
      </IconButton>
    </Tooltip>
    <NotificationDropdown organizationId={organizationId} recipientId={recipientId} anchorEl={anchorEl} open={open}
      onClose={handleClose} onMarkAllRead={handleMarkAllRead} onCountChange={loadUnreadCount} />
  </>;
}
export default function NotificationBell() {
  const { activeOrgId } = useConsole(); const { user } = useAuth(); const { can, isLoading } = usePermissions();
  const recipientId = user?.sub || user?.id || user?.user_id;
  if (!activeOrgId || !recipientId || isLoading || !can('notification', 'view')) return null;
  return <ScopedNotificationBell key={`${activeOrgId}:${recipientId}`} organizationId={activeOrgId} recipientId={recipientId} />;
}
