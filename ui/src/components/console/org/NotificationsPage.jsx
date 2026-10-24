import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, LinearProgress,
  Paper, Stack, Tab, Tabs, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { ResourcePage } from '../../common';
import notificationsApi from '../../../services/notificationsApi';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAuth } from '../../../hooks/useAuth';
import { useTranslation } from 'react-i18next';

const PAGE_SIZE = 25;
function dateLabel(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Not recorded' : date.toLocaleString();
}
function DeliveryResults({ notificationId, organizationId }) {
  const [state, setState] = useState({ loading: true, results: [], error: '' });
  const [attempt, setAttempt] = useState(0);
  const [page, setPage] = useState(0);
  useEffect(() => {
    let current = true; setState({ loading: true, results: [], error: '' });
    notificationsApi.getNotificationDeliveryResults(notificationId, organizationId, { limit: PAGE_SIZE, offset: page * PAGE_SIZE }).then((result) => {
      if (!Array.isArray(result) || !result.every((item) => item?.notification_id === notificationId
        && typeof item.channel === 'string' && typeof item.success === 'boolean')) {
        throw new Error('Delivery results do not match the selected notification.');
      }
      if (current) setState({ loading: false, results: result, error: '' });
    }).catch((error) => { if (current) setState({ loading: false, results: [], error: error?.message || 'Delivery results could not be loaded.' }); });
    return () => { current = false; };
  }, [notificationId, organizationId, attempt, page]);
  return <Stack spacing={1}>
    <Alert severity="info">A notification accepted by the API is not proof of delivery. These are recorded transport attempts.</Alert>
    {state.loading && <LinearProgress />}
    {state.error && <Alert severity="error">{state.error}<Button onClick={() => setAttempt((value) => value + 1)}>Retry delivery results</Button></Alert>}
    {!state.loading && !state.error && !state.results.length && <Typography>No delivery attempts recorded.</Typography>}
    {state.results.map((result, index) => <Paper key={`${result.channel}-${index}`} variant="outlined" sx={{ p: 2 }}>
      <Typography>{result.channel}: {result.success ? 'Succeeded' : 'Failed'}</Typography>
      <Typography variant="body2">Attempted: {dateLabel(result.attempted_at)}</Typography>
      {result.error_code && <Typography variant="body2">Error code: {result.error_code}</Typography>}
      {result.should_retry != null && <Typography variant="body2">Retry advised: {result.should_retry ? 'Yes' : 'No'}</Typography>}
    </Paper>)}
    <Stack direction="row" spacing={1}><Button disabled={state.loading || page === 0} onClick={() => setPage((value) => value - 1)}>Previous attempts</Button>
      <Typography sx={{ alignSelf: 'center' }}>Page {page + 1}</Typography>
      <Button disabled={state.loading || Boolean(state.error) || state.results.length < PAGE_SIZE} onClick={() => setPage((value) => value + 1)}>Next attempts</Button></Stack>
  </Stack>;
}
function NotificationInbox({ organizationId, recipientId }) {
  const { t } = useTranslation('console');
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [tab, setTab] = useState('inbox');
  const [page, setPage] = useState(0);
  const [unread, setUnread] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState({ loading: true, items: [], error: '' });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const [deleting, setDeleting] = useState(null);
  const [details, setDetails] = useState(null);
  useEffect(() => {
    let current = true;
    setState({ loading: true, items: [], error: '' });
    notificationsApi.listNotifications({ organization_id: organizationId, recipient_id: recipientId,
      unread_only: unread, limit: PAGE_SIZE, offset: page * PAGE_SIZE }).then((items) => {
      if (current) setState({ loading: false, items, error: '' });
    }).catch((error) => { if (current) setState({ loading: false, items: [], error: error?.message || 'Notifications could not be loaded.' }); });
    return () => { current = false; };
  }, [organizationId, recipientId, page, unread, attempt]);
  const mutate = async (operation) => {
    if (busy) return;
    setBusy(true); setActionError('');
    try {
      await operation();
      if (!mounted.current) return;
      setDeleting(null); setAttempt((value) => value + 1);
    } catch (error) { if (mounted.current) setActionError(error?.message || 'Notification could not be updated.'); }
    finally { if (mounted.current) setBusy(false); }
  };
  return <ResourcePage title={t('org.notifications.title')} description="Your notification inbox in the selected organization.">
    <Tabs value={tab} onChange={(_event, value) => setTab(value)} sx={{ mb: 2 }}>
      <Tab value="inbox" label="Inbox" /><Tab value="support" label="API support" />
    </Tabs>
    {tab === 'support' ? <Stack spacing={2}>
      <Alert severity="info">Notification targets are supported inside send requests. They are not standalone saved profiles.</Alert>
      <Typography>The send API accepts a target with organization, user, device, email or webhook destinations and channels. It requires notification:send permission. Transport configuration and recorded delivery results determine whether a notification is delivered.</Typography>
      <Alert severity="info">Alert rules and notification preference read/update operations are not supported by the notification API. This console does not offer editors that cannot save.</Alert>
      <Button href="/openapi.json" sx={{ alignSelf: 'flex-start' }}>View API contract</Button>
    </Stack> : <Stack spacing={2}>
      <Stack direction="row" spacing={1}>
        <Button variant={!unread ? 'contained' : 'outlined'} disabled={busy} onClick={() => { setUnread(false); setPage(0); }}>{t('org.notifications.notificationsTab.filterAll')}</Button>
        <Button variant={unread ? 'contained' : 'outlined'} disabled={busy} onClick={() => { setUnread(true); setPage(0); }}>{t('org.notifications.notificationsTab.filterUnread')}</Button>
        <Button disabled={busy || state.loading} onClick={() => mutate(() => notificationsApi.markAllAsRead(organizationId, recipientId))}>{t('org.notifications.notificationsTab.markAllAsRead')}</Button>
      </Stack>
      {actionError && <Alert severity="error">{actionError}</Alert>}
      {state.loading && <LinearProgress />}
      {state.error && <Alert severity="error">{state.error}<Button onClick={() => setAttempt((value) => value + 1)}>Retry notifications</Button></Alert>}
      {!state.loading && !state.error && (state.items.length ? <Paper variant="outlined"><Table>
        <TableHead><TableRow>{['title', 'message', 'time', 'state', 'actions'].map((label) => <TableCell key={label}>{t(`org.notifications.notificationsTab.tableHeaders.${label}`, { defaultValue: 'State' })}</TableCell>)}</TableRow></TableHead>
        <TableBody>{state.items.map((item) => <TableRow key={item.id}>
          <TableCell>{item.title}</TableCell><TableCell>{item.body}</TableCell><TableCell>{dateLabel(item.created_at)}</TableCell>
          <TableCell><Chip size="small" label={t(`org.notifications.notificationsTab.${item.read ? 'filterRead' : 'filterUnread'}`)} /></TableCell>
          <TableCell><Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
            {!item.read && <Button disabled={busy} onClick={() => mutate(() => notificationsApi.markAsRead(item.id, organizationId))}>{t('org.notifications.notificationsTab.actions.markAsRead')}</Button>}
            {item.read && <Button disabled={busy} onClick={() => mutate(() => notificationsApi.markAsUnread(item.id, organizationId))}>{t('org.notifications.notificationsTab.actions.markAsUnread', { defaultValue: 'Mark as unread' })}</Button>}
            <Button onClick={() => setDetails(item)}>Delivery results</Button>
            <Button disabled={busy} onClick={() => setDeleting(item)}>{t('org.notifications.notificationsTab.actions.delete')}</Button>
          </Stack></TableCell>
        </TableRow>)}</TableBody>
      </Table></Paper> : <Typography>No notifications on this page.</Typography>)}
      <Stack direction="row" spacing={2}><Button disabled={busy || state.loading || page === 0} onClick={() => setPage((value) => value - 1)}>Previous page</Button>
        <Typography sx={{ alignSelf: 'center' }}>Page {page + 1}</Typography>
        <Button disabled={busy || state.loading || Boolean(state.error) || state.items.length < PAGE_SIZE} onClick={() => setPage((value) => value + 1)}>Next page</Button></Stack>
    </Stack>}
    <Dialog open={Boolean(deleting)} onClose={() => !busy && setDeleting(null)}>
      <DialogTitle>Delete notification?</DialogTitle><DialogContent>{deleting?.title}</DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setDeleting(null)}>Cancel</Button>
        <Button disabled={busy} onClick={() => mutate(() => notificationsApi.deleteNotification(deleting.id, organizationId))}>Confirm deletion</Button></DialogActions>
    </Dialog>
    <Dialog open={Boolean(details)} onClose={() => setDetails(null)} fullWidth maxWidth="sm">
      <DialogTitle>Delivery results</DialogTitle><DialogContent>{details && <Box sx={{ py: 1 }}><DeliveryResults key={details.id} notificationId={details.id} organizationId={organizationId} /></Box>}</DialogContent>
      <DialogActions><Button onClick={() => setDetails(null)}>Close</Button></DialogActions>
    </Dialog>
  </ResourcePage>;
}
export default function NotificationsPage() {
  const { activeOrgId } = useConsole();
  const { user } = useAuth();
  const { can, isLoading } = usePermissions();
  const recipientId = user?.sub || user?.id || user?.user_id;
  if (!activeOrgId) return <Alert severity="error">Select an organization before loading notifications.</Alert>;
  if (isLoading) return <LinearProgress />;
  if (!can('notification', 'view')) return <Alert severity="error">You do not have permission to view notifications.</Alert>;
  if (!recipientId) return <Alert severity="error">Sign in before loading your notification inbox.</Alert>;
  return <NotificationInbox key={`${activeOrgId}:${recipientId}`} organizationId={activeOrgId} recipientId={recipientId} />;
}
