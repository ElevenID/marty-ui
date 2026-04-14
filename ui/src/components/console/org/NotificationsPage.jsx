import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DraftsIcon from '@mui/icons-material/Drafts';
import MailIcon from '@mui/icons-material/Mail';
import NotificationsIcon from '@mui/icons-material/Notifications';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { formatDistanceToNow } from 'date-fns';
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import ErrorState from '../../common/ErrorState';
import EmptyState from '../../common/EmptyState';
import notificationsApi from '../../../services/notificationsApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { usePermissions } from '../../../hooks/usePermissions';

/**
 * NotificationsPage - Full page for managing notifications and alert rules
 * 
 * Tabbed interface with:
 * - Notifications: List of all notifications with read/unread filter
 * - Alert Rules: Configure notification rules for events
 * - Preferences: Email/push notification settings
 */
function NotificationsPage() {
  const { t } = useTranslation('console');
  const [activeTab, setActiveTab] = useState(0);
  const { can } = usePermissions();
  const canManageNotifications = can('notification', 'send');
  
  return (
    <ResourcePage
      title={t('org.notifications.title')}
      subtitle={t('org.notifications.subtitle')}
      icon={<NotificationsIcon />}
      pageTestId="org.notifications.page"
    >
      <Paper sx={{ mb: 2 }}>
        <Tabs value={activeTab} onChange={(e, val) => setActiveTab(val)}>
          <Tab label={t('org.notifications.tabs.notifications')} />
          <Tab label={t('org.notifications.tabs.alertRules')} />
          <Tab label={t('org.notifications.tabs.preferences')} />
        </Tabs>
      </Paper>

      {activeTab === 0 && <NotificationsTab t={t} />}
      {activeTab === 1 && <AlertRulesTab t={t} canManageNotifications={canManageNotifications} />}
      {activeTab === 2 && <PreferencesTab t={t} canManageNotifications={canManageNotifications} />}
    </ResourcePage>
  );
}

function NotificationsTab({ t }) {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  const [filter, setFilter] = useState('all'); // all, unread, read

  const { showNotification } = useNotifications();

  useEffect(() => {
    loadNotifications();
  }, [page, rowsPerPage, filter]);

  const loadNotifications = async () => {
    setLoading(true);
    setError(null);
    try {
      const filters = {
        limit: rowsPerPage,
        offset: page * rowsPerPage,
      };
      if (filter === 'unread') filters.unread_only = true;

      const data = await notificationsApi.listNotifications(filters);
      const allNotifications = Array.isArray(data) ? data : data.notifications || [];

      // The backend currently supports `unread_only` but not a dedicated
      // `read_only` query flag, so the "read" filter is narrowed client-side.
      const visibleNotifications = filter === 'read'
        ? allNotifications.filter((notification) => notification.read)
        : allNotifications;

      setNotifications(visibleNotifications);
      setTotalCount(
        filter === 'read'
          ? visibleNotifications.length
          : (data.total || allNotifications.length || 0)
      );
    } catch (err) {
      console.error('Failed to load notifications:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleMarkAsRead = async (notificationId) => {
    try {
      await notificationsApi.markAsRead(notificationId);
      loadNotifications();
    } catch (err) {
      console.error('Failed to mark as read:', err);
      showNotification?.(t('org.notifications.notificationsTab.error.markAsRead'), 'error');
    }
  };

  const handleMarkAllAsRead = async () => {
    try {
      await notificationsApi.markAllAsRead();
      showNotification?.(t('org.notifications.notificationsTab.success.markAllAsRead'), 'success');
      loadNotifications();
    } catch (err) {
      console.error('Failed to mark all as read:', err);
      showNotification?.(t('org.notifications.notificationsTab.error.markAllAsRead'), 'error');
    }
  };

  const handleDelete = async (notificationId) => {
    if (!confirm(t('org.notifications.notificationsTab.confirmDelete'))) return;
    try {
      await notificationsApi.deleteNotification(notificationId);
      showNotification?.(t('org.notifications.notificationsTab.success.deleted'), 'success');
      loadNotifications();
    } catch (err) {
      console.error('Failed to delete notification:', err);
      showNotification?.(t('org.notifications.notificationsTab.error.delete'), 'error');
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'error': return <ErrorIcon color="error" />;
      case 'warning': return <WarningIcon color="warning" />;
      case 'success': return <CheckCircleIcon color="success" />;
      default: return <InfoIcon color="info" />;
    }
  };

  return (
    <>
      <Paper sx={{ p: 2, mb: 2, display: 'flex', gap: 2, alignItems: 'center' }}>
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel>{t('org.notifications.notificationsTab.filter')}</InputLabel>
          <Select value={filter} label={t('org.notifications.notificationsTab.filter')} onChange={(e) => setFilter(e.target.value)}>
            <MenuItem value="all">{t('org.notifications.notificationsTab.filterAll')}</MenuItem>
            <MenuItem value="unread">{t('org.notifications.notificationsTab.filterUnread')}</MenuItem>
            <MenuItem value="read">{t('org.notifications.notificationsTab.filterRead')}</MenuItem>
          </Select>
        </FormControl>
        {notifications.some(n => !n.read) && (
          <Button size="small" variant="outlined" onClick={handleMarkAllAsRead}>
            {t('org.notifications.notificationsTab.markAllAsRead')}
          </Button>
        )}
      </Paper>

      {loading ? (
        <TableSkeleton rows={rowsPerPage} columns={4} showActions />
      ) : error ? (
        <ErrorState error={error} onRetry={loadNotifications} variant="inline" />
      ) : notifications.length === 0 ? (
        <EmptyState
          icon={MailIcon}
          title={t('org.notifications.notificationsTab.empty.title')}
          description={filter === 'unread' ? t('org.notifications.notificationsTab.empty.descriptionUnread') : t('org.notifications.notificationsTab.empty.descriptionAll')}
        />
      ) : (
        <>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell width="5%"></TableCell>
                  <TableCell width="40%">{t('org.notifications.notificationsTab.tableHeaders.title')}</TableCell>
                  <TableCell width="30%">{t('org.notifications.notificationsTab.tableHeaders.message')}</TableCell>
                  <TableCell width="15%">{t('org.notifications.notificationsTab.tableHeaders.time')}</TableCell>
                  <TableCell width="10%" align="right">{t('org.notifications.notificationsTab.tableHeaders.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {notifications.map((notification) => (
                  <TableRow
                    key={notification.id}
                    sx={{ bgcolor: notification.read ? 'transparent' : 'action.hover' }}
                  >
                    <TableCell>{getSeverityIcon(notification.severity)}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: notification.read ? 400 : 600 }}>
                        {notification.title}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {notification.message}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" color="text.disabled">
                        {formatDistanceToNow(new Date(notification.created_at), { addSuffix: true })}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      {!notification.read && (
                        <IconButton
                          size="small"
                          onClick={() => handleMarkAsRead(notification.id)}
                          title={t('org.notifications.notificationsTab.actions.markAsRead')}
                        >
                          <DraftsIcon fontSize="small" />
                        </IconButton>
                      )}
                      <IconButton
                        size="small"
                        onClick={() => handleDelete(notification.id)}
                        title={t('org.notifications.notificationsTab.actions.delete')}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            component="div"
            count={totalCount}
            page={page}
            onPageChange={(e, newPage) => setPage(newPage)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(e) => {
              setRowsPerPage(parseInt(e.target.value, 10));
              setPage(0);
            }}
          />
        </>
      )}
    </>
  );
}

function AlertRulesTab({ t, canManageNotifications }) {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);

  const { showNotification } = useNotifications();

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await notificationsApi.listAlertRules();
      setRules(Array.isArray(data) ? data : data.rules || []);
    } catch (err) {
      console.error('Failed to load alert rules:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    if (!canManageNotifications) return;
    setEditingRule(null);
    setDialogOpen(true);
  };

  const handleEdit = (rule) => {
    if (!canManageNotifications) return;
    setEditingRule(rule);
    setDialogOpen(true);
  };

  const handleDelete = async (ruleId) => {
    if (!canManageNotifications) return;
    if (!confirm(t('org.notifications.alertRulesTab.confirmDelete'))) return;
    try {
      await notificationsApi.deleteAlertRule(ruleId);
      showNotification?.(t('org.notifications.alertRulesTab.success.deleted'), 'success');
      loadRules();
    } catch (err) {
      console.error('Failed to delete alert rule:', err);
      showNotification?.(t('org.notifications.alertRulesTab.error.delete'), 'error');
    }
  };

  const handleSave = async (ruleData) => {
    if (!canManageNotifications) return;
    try {
      if (editingRule) {
        await notificationsApi.updateAlertRule(editingRule.id, ruleData);
        showNotification?.(t('org.notifications.alertRulesTab.success.updated'), 'success');
      } else {
        await notificationsApi.createAlertRule(ruleData);
        showNotification?.(t('org.notifications.alertRulesTab.success.created'), 'success');
      }
      setDialogOpen(false);
      loadRules();
    } catch (err) {
      console.error('Failed to save alert rule:', err);
      showNotification?.(t('org.notifications.alertRulesTab.error.save'), 'error');
    }
  };

  return (
    <>
      {!canManageNotifications && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('org.notifications.alertRulesTab.readOnlyNotice')}
        </Alert>
      )}

      {canManageNotifications && (
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'flex-end' }}>
          <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
            {t('org.notifications.alertRulesTab.create')}
          </Button>
        </Box>
      )}

      {loading ? (
        <TableSkeleton rows={5} columns={4} showActions />
      ) : error ? (
        <ErrorState error={error} onRetry={loadRules} variant="inline" />
      ) : rules.length === 0 ? (
        <EmptyState
          icon={NotificationsIcon}
          title={t('org.notifications.alertRulesTab.empty.title')}
          description={t('org.notifications.alertRulesTab.empty.description')}
          action={canManageNotifications ? (
            <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
              {t('org.notifications.alertRulesTab.createFirst')}
            </Button>
          ) : null}
        />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('org.notifications.alertRulesTab.tableHeaders.name')}</TableCell>
                <TableCell>{t('org.notifications.alertRulesTab.tableHeaders.eventType')}</TableCell>
                <TableCell>{t('org.notifications.alertRulesTab.tableHeaders.severity')}</TableCell>
                <TableCell>{t('org.notifications.alertRulesTab.tableHeaders.enabled')}</TableCell>
                <TableCell align="right">{t('org.notifications.alertRulesTab.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>{rule.name}</TableCell>
                  <TableCell>
                    <Chip label={rule.event_type} size="small" />
                  </TableCell>
                  <TableCell>
                    <Chip label={rule.severity} size="small" color={
                      rule.severity === 'error' ? 'error' :
                      rule.severity === 'warning' ? 'warning' : 'default'
                    } />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={rule.enabled ? t('org.notifications.alertRulesTab.status.enabled') : t('org.notifications.alertRulesTab.status.disabled')}
                      size="small"
                      color={rule.enabled ? 'success' : 'default'}
                    />
                  </TableCell>
                  <TableCell align="right">
                    {canManageNotifications && (
                      <>
                        <IconButton size="small" onClick={() => handleEdit(rule)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" onClick={() => handleDelete(rule.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <AlertRuleDialog
        open={dialogOpen}
        rule={editingRule}
        onClose={() => setDialogOpen(false)}
        onSave={handleSave}
        t={t}
      />
    </>
  );
}

function AlertRuleDialog({ open, rule, onClose, onSave, t }) {
  const [formData, setFormData] = useState({
    name: '',
    event_type: '',
    severity: 'info',
    enabled: true,
  });

  useEffect(() => {
    if (rule) {
      setFormData(rule);
    } else {
      setFormData({ name: '', event_type: '', severity: 'info', enabled: true });
    }
  }, [rule, open]);

  const handleSubmit = () => {
    onSave(formData);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{rule ? t('org.notifications.alertRulesTab.dialog.titleEdit') : t('org.notifications.alertRulesTab.dialog.titleCreate')}</DialogTitle>
      <DialogContent>
        <TextField
          fullWidth
          label={t('org.notifications.alertRulesTab.dialog.nameLabel')}
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          margin="normal"
        />
        <FormControl fullWidth margin="normal">
          <InputLabel>{t('org.notifications.alertRulesTab.dialog.eventTypeLabel')}</InputLabel>
          <Select
            value={formData.event_type}
            label={t('org.notifications.alertRulesTab.dialog.eventTypeLabel')}
            onChange={(e) => setFormData({ ...formData, event_type: e.target.value })}
          >
            <MenuItem value="credential.issued">{t('org.notifications.alertRulesTab.eventTypes.credentialIssued')}</MenuItem>
            <MenuItem value="credential.revoked">{t('org.notifications.alertRulesTab.eventTypes.credentialRevoked')}</MenuItem>
            <MenuItem value="flow.failed">{t('org.notifications.alertRulesTab.eventTypes.flowFailed')}</MenuItem>
            <MenuItem value="authentication.failed">{t('org.notifications.alertRulesTab.eventTypes.authenticationFailed')}</MenuItem>
            <MenuItem value="key.expiring">{t('org.notifications.alertRulesTab.eventTypes.keyExpiring')}</MenuItem>
            <MenuItem value="quota.warning">{t('org.notifications.alertRulesTab.eventTypes.quotaWarning')}</MenuItem>
          </Select>
        </FormControl>
        <FormControl fullWidth margin="normal">
          <InputLabel>{t('org.notifications.alertRulesTab.dialog.severityLabel')}</InputLabel>
          <Select
            value={formData.severity}
            label={t('org.notifications.alertRulesTab.dialog.severityLabel')}
            onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
          >
            <MenuItem value="info">{t('org.notifications.alertRulesTab.severity.info')}</MenuItem>
            <MenuItem value="warning">{t('org.notifications.alertRulesTab.severity.warning')}</MenuItem>
            <MenuItem value="error">{t('org.notifications.alertRulesTab.severity.error')}</MenuItem>
          </Select>
        </FormControl>
        <FormControlLabel
          control={
            <Switch
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
            />
          }
          label={t('org.notifications.alertRulesTab.dialog.enabledLabel')}
          sx={{ mt: 2 }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('actions.cancel', { ns: 'common' })}</Button>
        <Button onClick={handleSubmit} variant="contained">
          {rule ? t('org.notifications.alertRulesTab.dialog.buttonUpdate') : t('org.notifications.alertRulesTab.dialog.buttonCreate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function PreferencesTab({ t, canManageNotifications }) {
  const [preferences, setPreferences] = useState({
    email_notifications: true,
    push_notifications: false,
    digest_enabled: false,
    digest_frequency: 'daily',
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const { showNotification } = useNotifications();

  useEffect(() => {
    loadPreferences();
  }, []);

  const loadPreferences = async () => {
    setLoading(true);
    try {
      const data = await notificationsApi.getNotificationPreferences();
      setPreferences(data || preferences);
    } catch (err) {
      console.error('Failed to load preferences:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await notificationsApi.updateNotificationPreferences(preferences);
      showNotification?.(t('org.notifications.preferencesTab.success'), 'success');
    } catch (err) {
      console.error('Failed to update preferences:', err);
      showNotification?.(t('org.notifications.preferencesTab.error'), 'error');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <TableSkeleton rows={5} columns={1} showActions={false} />;

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        {t('org.notifications.preferencesTab.title')}
      </Typography>
      <Divider sx={{ my: 2 }} />
      
      <FormControlLabel
        control={
          <Switch
            checked={preferences.email_notifications}
            onChange={(e) => setPreferences({ ...preferences, email_notifications: e.target.checked })}
            disabled={!canManageNotifications}
          />
        }
        label={t('org.notifications.preferencesTab.emailNotifications.label')}
        sx={{ display: 'block', mb: 2 }}
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 5, mb: 3 }}>
        {t('org.notifications.preferencesTab.emailNotifications.description')}
      </Typography>

      <FormControlLabel
        control={
          <Switch
            checked={preferences.push_notifications}
            onChange={(e) => setPreferences({ ...preferences, push_notifications: e.target.checked })}
            disabled={!canManageNotifications}
          />
        }
        label={t('org.notifications.preferencesTab.pushNotifications.label')}
        sx={{ display: 'block', mb: 2 }}
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 5, mb: 3 }}>
        {t('org.notifications.preferencesTab.pushNotifications.description')}
      </Typography>

      <FormControlLabel
        control={
          <Switch
            checked={preferences.digest_enabled}
            onChange={(e) => setPreferences({ ...preferences, digest_enabled: e.target.checked })}
            disabled={!canManageNotifications}
          />
        }
        label={t('org.notifications.preferencesTab.digest.label')}
        sx={{ display: 'block', mb: 2 }}
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 5, mb: 3 }}>
        {t('org.notifications.preferencesTab.digest.description')}
      </Typography>

      {preferences.digest_enabled && (
        <FormControl sx={{ ml: 5, mb: 3, minWidth: 200 }}>
          <InputLabel>{t('org.notifications.preferencesTab.digestFrequency.label')}</InputLabel>
          <Select
            value={preferences.digest_frequency}
            label={t('org.notifications.preferencesTab.digestFrequency.label')}
            onChange={(e) => setPreferences({ ...preferences, digest_frequency: e.target.value })}
            disabled={!canManageNotifications}
          >
            <MenuItem value="daily">{t('org.notifications.preferencesTab.digestFrequency.daily')}</MenuItem>
            <MenuItem value="weekly">{t('org.notifications.preferencesTab.digestFrequency.weekly')}</MenuItem>
          </Select>
        </FormControl>
      )}

      <Box sx={{ mt: 4 }}>
        {!canManageNotifications && (
          <Alert severity="info" sx={{ mb: 2 }}>
            {t('org.notifications.preferencesTab.readOnlyNotice')}
          </Alert>
        )}
        <Button variant="contained" onClick={handleSave} disabled={saving || !canManageNotifications}>
          {saving ? t('org.notifications.preferencesTab.saving') : t('org.notifications.preferencesTab.saveButton')}
        </Button>
      </Box>
    </Paper>
  );
}

export default NotificationsPage;
