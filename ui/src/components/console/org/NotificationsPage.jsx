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

import { ResourcePage } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import ErrorState from '../../common/ErrorState';
import EmptyState from '../../common/EmptyState';
import notificationsApi from '../../../services/notificationsApi';
import { useNotifications } from '../../../hooks/useNotifications';

/**
 * NotificationsPage - Full page for managing notifications and alert rules
 * 
 * Tabbed interface with:
 * - Notifications: List of all notifications with read/unread filter
 * - Alert Rules: Configure notification rules for events
 * - Preferences: Email/push notification settings
 */
function NotificationsPage() {
  const [activeTab, setActiveTab] = useState(0);
  
  return (
    <ResourcePage
      title="Notifications"
      subtitle="Manage notifications, alert rules, and preferences"
      icon={<NotificationsIcon />}
    >
      <Paper sx={{ mb: 2 }}>
        <Tabs value={activeTab} onChange={(e, val) => setActiveTab(val)}>
          <Tab label="Notifications" />
          <Tab label="Alert Rules" />
          <Tab label="Preferences" />
        </Tabs>
      </Paper>

      {activeTab === 0 && <NotificationsTab />}
      {activeTab === 1 && <AlertRulesTab />}
      {activeTab === 2 && <PreferencesTab />}
    </ResourcePage>
  );
}

function NotificationsTab() {
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
      if (filter === 'unread') filters.read = false;
      if (filter === 'read') filters.read = true;

      const data = await notificationsApi.listNotifications(filters);
      setNotifications(Array.isArray(data) ? data : data.notifications || []);
      setTotalCount(data.total || data.length || 0);
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
      showNotification?.('Failed to mark notification as read', 'error');
    }
  };

  const handleMarkAllAsRead = async () => {
    try {
      await notificationsApi.markAllAsRead();
      showNotification?.('All notifications marked as read', 'success');
      loadNotifications();
    } catch (err) {
      console.error('Failed to mark all as read:', err);
      showNotification?.('Failed to mark all as read', 'error');
    }
  };

  const handleDelete = async (notificationId) => {
    if (!confirm('Delete this notification?')) return;
    try {
      await notificationsApi.deleteNotification(notificationId);
      showNotification?.('Notification deleted', 'success');
      loadNotifications();
    } catch (err) {
      console.error('Failed to delete notification:', err);
      showNotification?.('Failed to delete notification', 'error');
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
          <InputLabel>Filter</InputLabel>
          <Select value={filter} label="Filter" onChange={(e) => setFilter(e.target.value)}>
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="unread">Unread</MenuItem>
            <MenuItem value="read">Read</MenuItem>
          </Select>
        </FormControl>
        {notifications.some(n => !n.read) && (
          <Button size="small" variant="outlined" onClick={handleMarkAllAsRead}>
            Mark All as Read
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
          title="No notifications"
          description={filter === 'unread' ? "You have no unread notifications." : "You don't have any notifications yet."}
        />
      ) : (
        <>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell width="5%"></TableCell>
                  <TableCell width="40%">Title</TableCell>
                  <TableCell width="30%">Message</TableCell>
                  <TableCell width="15%">Time</TableCell>
                  <TableCell width="10%" align="right">Actions</TableCell>
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
                          title="Mark as read"
                        >
                          <DraftsIcon fontSize="small" />
                        </IconButton>
                      )}
                      <IconButton
                        size="small"
                        onClick={() => handleDelete(notification.id)}
                        title="Delete"
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

function AlertRulesTab() {
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
    setEditingRule(null);
    setDialogOpen(true);
  };

  const handleEdit = (rule) => {
    setEditingRule(rule);
    setDialogOpen(true);
  };

  const handleDelete = async (ruleId) => {
    if (!confirm('Delete this alert rule?')) return;
    try {
      await notificationsApi.deleteAlertRule(ruleId);
      showNotification?.('Alert rule deleted', 'success');
      loadRules();
    } catch (err) {
      console.error('Failed to delete alert rule:', err);
      showNotification?.('Failed to delete alert rule', 'error');
    }
  };

  const handleSave = async (ruleData) => {
    try {
      if (editingRule) {
        await notificationsApi.updateAlertRule(editingRule.id, ruleData);
        showNotification?.('Alert rule updated', 'success');
      } else {
        await notificationsApi.createAlertRule(ruleData);
        showNotification?.('Alert rule created', 'success');
      }
      setDialogOpen(false);
      loadRules();
    } catch (err) {
      console.error('Failed to save alert rule:', err);
      showNotification?.('Failed to save alert rule', 'error');
    }
  };

  return (
    <>
      <Box sx={{ mb: 2, display: 'flex', justifyContent: 'flex-end' }}>
        <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
          Create Alert Rule
        </Button>
      </Box>

      {loading ? (
        <TableSkeleton rows={5} columns={4} showActions />
      ) : error ? (
        <ErrorState error={error} onRetry={loadRules} variant="inline" />
      ) : rules.length === 0 ? (
        <EmptyState
          icon={NotificationsIcon}
          title="No alert rules"
          description="Create alert rules to get notified about important events."
          action={
            <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
              Create First Rule
            </Button>
          }
        />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Event Type</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Enabled</TableCell>
                <TableCell align="right">Actions</TableCell>
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
                      label={rule.enabled ? 'Enabled' : 'Disabled'}
                      size="small"
                      color={rule.enabled ? 'success' : 'default'}
                    />
                  </TableCell>
                  <TableCell align="right">
                    <IconButton size="small" onClick={() => handleEdit(rule)}>
                      <EditIcon fontSize="small" />
                    </IconButton>
                    <IconButton size="small" onClick={() => handleDelete(rule.id)}>
                      <DeleteIcon fontSize="small" />
                    </IconButton>
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
      />
    </>
  );
}

function AlertRuleDialog({ open, rule, onClose, onSave }) {
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
      <DialogTitle>{rule ? 'Edit Alert Rule' : 'Create Alert Rule'}</DialogTitle>
      <DialogContent>
        <TextField
          fullWidth
          label="Rule Name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          margin="normal"
        />
        <FormControl fullWidth margin="normal">
          <InputLabel>Event Type</InputLabel>
          <Select
            value={formData.event_type}
            label="Event Type"
            onChange={(e) => setFormData({ ...formData, event_type: e.target.value })}
          >
            <MenuItem value="credential.issued">Credential Issued</MenuItem>
            <MenuItem value="credential.revoked">Credential Revoked</MenuItem>
            <MenuItem value="flow.failed">Flow Failed</MenuItem>
            <MenuItem value="authentication.failed">Authentication Failed</MenuItem>
            <MenuItem value="key.expiring">Signing Key Expiring</MenuItem>
            <MenuItem value="quota.warning">Quota Warning</MenuItem>
          </Select>
        </FormControl>
        <FormControl fullWidth margin="normal">
          <InputLabel>Severity</InputLabel>
          <Select
            value={formData.severity}
            label="Severity"
            onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
          >
            <MenuItem value="info">Info</MenuItem>
            <MenuItem value="warning">Warning</MenuItem>
            <MenuItem value="error">Error</MenuItem>
          </Select>
        </FormControl>
        <FormControlLabel
          control={
            <Switch
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
            />
          }
          label="Enabled"
          sx={{ mt: 2 }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained">
          {rule ? 'Update' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function PreferencesTab() {
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
      showNotification?.('Preferences updated', 'success');
    } catch (err) {
      console.error('Failed to update preferences:', err);
      showNotification?.('Failed to update preferences', 'error');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <TableSkeleton rows={5} columns={1} showActions={false} />;

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        Notification Preferences
      </Typography>
      <Divider sx={{ my: 2 }} />
      
      <FormControlLabel
        control={
          <Switch
            checked={preferences.email_notifications}
            onChange={(e) => setPreferences({ ...preferences, email_notifications: e.target.checked })}
          />
        }
        label="Email Notifications"
        sx={{ display: 'block', mb: 2 }}
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 5, mb: 3 }}>
        Receive notifications via email
      </Typography>

      <FormControlLabel
        control={
          <Switch
            checked={preferences.push_notifications}
            onChange={(e) => setPreferences({ ...preferences, push_notifications: e.target.checked })}
          />
        }
        label="Push Notifications"
        sx={{ display: 'block', mb: 2 }}
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 5, mb: 3 }}>
        Receive browser push notifications
      </Typography>

      <FormControlLabel
        control={
          <Switch
            checked={preferences.digest_enabled}
            onChange={(e) => setPreferences({ ...preferences, digest_enabled: e.target.checked })}
          />
        }
        label="Daily Digest"
        sx={{ display: 'block', mb: 2 }}
      />
      <Typography variant="body2" color="text.secondary" sx={{ ml: 5, mb: 3 }}>
        Receive a summary of notifications
      </Typography>

      {preferences.digest_enabled && (
        <FormControl sx={{ ml: 5, mb: 3, minWidth: 200 }}>
          <InputLabel>Digest Frequency</InputLabel>
          <Select
            value={preferences.digest_frequency}
            label="Digest Frequency"
            onChange={(e) => setPreferences({ ...preferences, digest_frequency: e.target.value })}
          >
            <MenuItem value="daily">Daily</MenuItem>
            <MenuItem value="weekly">Weekly</MenuItem>
          </Select>
        </FormControl>
      )}

      <Box sx={{ mt: 4 }}>
        <Button variant="contained" onClick={handleSave} disabled={saving}>
          {saving ? 'Saving...' : 'Save Preferences'}
        </Button>
      </Box>
    </Paper>
  );
}

export default NotificationsPage;
