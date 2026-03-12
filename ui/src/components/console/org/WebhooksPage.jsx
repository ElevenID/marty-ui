/**
 * Webhooks Page
 * 
 * Manage webhook endpoints for event notifications.
 */

import { useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormGroup,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import HistoryIcon from '@mui/icons-material/History';
import { Link } from 'react-router-dom';

import { ResourcePage } from '../../common';

/**
 * Get deployment tabs with translations
 */
const getDeployTabs = (t) => [
  { label: t('deploy.tabs.profiles'), path: '/console/org/deploy/profiles' },
  { label: t('deploy.tabs.apiKeys'), path: '/console/org/deploy/api-keys' },
  { label: t('deploy.tabs.lanes'), path: '/console/org/deploy/lanes' },
  { label: t('org.tabs.webhooks'), path: '/console/org/deploy/webhooks' },
];

/**
 * Get breadcrumbs with translations
 */
const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: t('org.tabs.webhooks'), path: '/console/org/deploy/webhooks' },
];

/**
 * Get event types with translations
 */
const getEventTypes = (t) => [
  { value: 'flow.completed', label: t('org.webhooks.events.flowCompleted') },
  { value: 'flow.failed', label: t('org.webhooks.events.flowFailed') },
  { value: 'credential.issued', label: t('org.webhooks.events.credentialIssued') },
  { value: 'credential.revoked', label: t('org.webhooks.events.credentialRevoked') },
  { value: 'application.submitted', label: t('org.webhooks.events.applicationSubmitted') },
  { value: 'application.approved', label: t('org.webhooks.events.applicationApproved') },
  { value: 'application.rejected', label: t('org.webhooks.events.applicationRejected') },
];

function WebhooksPage() {
  const { t } = useTranslation('console');
  const { data: webhooks = [], loading, error } = useAsyncData(async () => {
    // TODO: Fetch webhooks from API
    await new Promise((resolve) => setTimeout(resolve, 500));
    return [
      {
        id: 'wh-1',
        url: 'https://api.example.com/webhooks/identity',
        events: ['flow.completed', 'flow.failed', 'credential.issued'],
        status: 'active',
        lastDelivery: '2026-02-07T09:00:00Z',
        successRate: 99.5,
      },
      {
        id: 'wh-2',
        url: 'https://crm.example.com/hooks/applications',
        events: ['application.submitted', 'application.approved'],
        status: 'active',
        lastDelivery: '2026-02-07T08:45:00Z',
        successRate: 100,
      },
    ];
  }, []);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newWebhook, setNewWebhook] = useState({
    url: '',
    events: [],
  });

  const handleCreate = async () => {
    // TODO: Create webhook via API
    setCreateDialogOpen(false);
    setNewWebhook({ url: '', events: [] });
  };

  const handleEventToggle = (eventValue) => {
    setNewWebhook((prev) => ({
      ...prev,
      events: prev.events.includes(eventValue)
        ? prev.events.filter((e) => e !== eventValue)
        : [...prev.events, eventValue],
    }));
  };

  return (
    <ResourcePage
      title={t('org.webhooks.title')}
      description={t('org.webhooks.description')}
      tabs={getDeployTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          {t('org.webhooks.addWebhook')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('org.webhooks.tableHeaders.url')}</TableCell>
                <TableCell>{t('org.webhooks.tableHeaders.events')}</TableCell>
                <TableCell>{t('org.webhooks.tableHeaders.lastDelivery')}</TableCell>
                <TableCell>{t('org.webhooks.tableHeaders.successRate')}</TableCell>
                <TableCell>{t('org.webhooks.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('org.webhooks.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {webhooks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('org.webhooks.empty')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                webhooks.map((webhook) => (
                  <TableRow key={webhook.id} hover>
                    <TableCell>
                      <Typography 
                        variant="body2" 
                        sx={{ 
                          fontFamily: 'monospace',
                          maxWidth: 300,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {webhook.url}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {webhook.events.slice(0, 2).map((event) => (
                          <Chip key={event} label={event} size="small" variant="outlined" />
                        ))}
                        {webhook.events.length > 2 && (
                          <Chip label={t('org.webhooks.moreEvents', { count: webhook.events.length - 2 })} size="small" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      {new Date(webhook.lastDelivery).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={`${webhook.successRate}%`} 
                        size="small" 
                        color={webhook.successRate >= 99 ? 'success' : webhook.successRate >= 90 ? 'warning' : 'error'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={webhook.status === 'active' ? t('org.webhooks.status.active') : t('org.webhooks.status.disabled')} 
                        color={webhook.status === 'active' ? 'success' : 'default'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('org.webhooks.actions.test')}>
                        <IconButton size="small" color="primary">
                          <PlayArrowIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('org.webhooks.actions.history')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/webhooks/${webhook.id}/history`}
                          size="small"
                        >
                          <HistoryIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('org.webhooks.actions.edit')}>
                        <IconButton size="small">
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('org.webhooks.actions.delete')}>
                        <IconButton size="small" color="error">
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create Webhook Dialog */}
      <Dialog 
        open={createDialogOpen} 
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t('org.webhooks.dialog.title')}</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <TextField
              autoFocus
              fullWidth
              label={t('org.webhooks.dialog.urlLabel')}
              placeholder={t('org.webhooks.dialog.urlPlaceholder')}
              value={newWebhook.url}
              onChange={(e) => setNewWebhook((prev) => ({ ...prev, url: e.target.value }))}
              sx={{ mb: 3 }}
            />
            <Typography variant="subtitle2" gutterBottom>
              {t('org.webhooks.dialog.eventsLabel')}
            </Typography>
            <FormGroup>
              {getEventTypes(t).map((event) => (
                <FormControlLabel
                  key={event.value}
                  control={
                    <Checkbox
                      checked={newWebhook.events.includes(event.value)}
                      onChange={() => handleEventToggle(event.value)}
                    />
                  }
                  label={event.label}
                />
              ))}
            </FormGroup>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>{t('actions.cancel', { ns: 'common' })}</Button>
          <Button 
            variant="contained" 
            onClick={handleCreate}
            disabled={!newWebhook.url.trim() || newWebhook.events.length === 0}
          >
            {t('org.webhooks.dialog.add')}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default WebhooksPage;
