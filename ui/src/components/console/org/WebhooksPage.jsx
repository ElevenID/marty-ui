/**
 * Webhooks Page
 *
 * Integration surface for external callbacks and audit forwarding.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  FormGroup,
  Grid,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import SecurityIcon from '@mui/icons-material/Security';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import EditIcon from '@mui/icons-material/Edit';

import { ResourcePage } from '../../common';
import ConfirmDeleteDialog from '../../common/ConfirmDeleteDialog';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import {
  createWebhook,
  deleteWebhook,
  getAvailableEventTypes,
  listWebhooks,
  testWebhook,
  updateWebhook,
} from '../../../services/webhooksApi';

const AUDIT_PRESET = [
  'audit.access_logged',
  'audit.configuration_changed',
  'audit.credential_accessed',
  'audit.export_performed',
  'audit.security_event',
  'audit.compliance_check',
];

const ASYNC_GATEWAY_PRESET = [
  'application.submitted',
  'application.approved',
  'application.rejected',
  'credential.issued',
  'credential.revoked',
  'verification.completed',
  'verification.failed',
  'verification.initiated',
];

const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: t('org.tabs.apiKeys', 'API Keys'), path: '/console/org/api-keys' },
  { label: t('org.tabs.webhooks'), path: '/console/org/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console', 'Console'), path: '/console' },
  { label: t('org.breadcrumbs.org', 'Org'), path: '/console/org' },
  { label: t('org.tabs.webhooks', 'Webhooks'), path: '/console/org/webhooks' },
];

function normalizeWebhook(webhook) {
  return {
    id: webhook?.id || '',
    url: webhook?.url || '',
    description: webhook?.description || '',
    eventTypes: Array.isArray(webhook?.event_types)
      ? webhook.event_types
      : Array.isArray(webhook?.events)
        ? webhook.events
        : [],
    enabled: webhook?.enabled ?? webhook?.status === 'active',
    lastTriggeredAt: webhook?.last_triggered_at || webhook?.lastDelivery || webhook?.last_delivery_at || null,
    secret: webhook?.secret || '',
  };
}

function formatDateTime(value) {
  if (!value) {
    return 'Never';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 'Never';
  }

  return parsed.toLocaleString();
}

async function copyToClipboard(text) {
  if (!text) {
    return false;
  }

  if (navigator?.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return true;
  }

  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.setAttribute('readonly', '');
  textArea.style.position = 'absolute';
  textArea.style.left = '-9999px';
  document.body.appendChild(textArea);
  textArea.select();
  const copied = document.execCommand('copy');
  document.body.removeChild(textArea);
  return copied;
}

function WebhooksPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState(null);
  const [pendingDelete, setPendingDelete] = useState(null);
  const [saving, setSaving] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [copiedMessage, setCopiedMessage] = useState('');
  const [createdSecret, setCreatedSecret] = useState('');
  const [formState, setFormState] = useState({
    url: '',
    description: '',
    eventTypes: [...ASYNC_GATEWAY_PRESET],
  });

  const { data, loading, error, reload } = useAsyncData(
    async () => {
      const [webhooks, eventCatalog] = await Promise.all([
        listWebhooks(organizationId),
        getAvailableEventTypes(),
      ]);

      return {
        webhooks: (webhooks || []).map(normalizeWebhook),
        eventCatalog: eventCatalog?.categories || [],
      };
    },
    [organizationId],
  );

  const webhooks = data?.webhooks || [];
  const eventCatalog = data?.eventCatalog || [];

  const resetDialog = () => {
    setDialogOpen(false);
    setEditingWebhook(null);
    setDialogError('');
    setCreatedSecret('');
    setFormState({
      url: '',
      description: '',
      eventTypes: [...ASYNC_GATEWAY_PRESET],
    });
  };

  const openCreateDialog = () => {
    setEditingWebhook(null);
    setCreatedSecret('');
    setDialogError('');
    setFormState({
      url: '',
      description: '',
      eventTypes: [...ASYNC_GATEWAY_PRESET],
    });
    setDialogOpen(true);
  };

  const openEditDialog = (webhook) => {
    setEditingWebhook(webhook);
    setCreatedSecret('');
    setDialogError('');
    setFormState({
      url: webhook.url,
      description: webhook.description,
      eventTypes: webhook.eventTypes,
    });
    setDialogOpen(true);
  };

  const toggleEventType = (eventType) => {
    setFormState((prev) => ({
      ...prev,
      eventTypes: prev.eventTypes.includes(eventType)
        ? prev.eventTypes.filter((value) => value !== eventType)
        : [...prev.eventTypes, eventType],
    }));
  };

  const applyPreset = (eventTypes) => {
    setFormState((prev) => ({
      ...prev,
      eventTypes: Array.from(new Set(eventTypes)),
    }));
  };

  const handleSave = async () => {
    if (!organizationId) {
      setDialogError('No active organization selected.');
      return;
    }

    if (!formState.url.trim()) {
      setDialogError('Enter a webhook URL.');
      return;
    }

    if (formState.eventTypes.length === 0) {
      setDialogError('Select at least one event type.');
      return;
    }

    setSaving(true);
    setDialogError('');

    try {
      if (editingWebhook) {
        await updateWebhook(editingWebhook.id, {
          url: formState.url.trim(),
          description: formState.description.trim(),
          eventTypes: formState.eventTypes,
          enabled: true,
        });
      } else {
        const created = await createWebhook(organizationId, {
          url: formState.url.trim(),
          description: formState.description.trim(),
          eventTypes: formState.eventTypes,
        });
        setCreatedSecret(created?.secret || '');
      }

      await reload();

      if (editingWebhook) {
        resetDialog();
      }
    } catch (saveError) {
      setDialogError(saveError instanceof Error ? saveError.message : String(saveError));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!pendingDelete) {
      return;
    }

    await deleteWebhook(pendingDelete.id);
    setPendingDelete(null);
    await reload();
  };

  const handleTest = async (webhookId) => {
    await testWebhook(webhookId);
    setCopiedMessage('Test delivery requested. Check the receiver for the signed callback.');
  };

  const handleCopySecret = async () => {
    const copied = await copyToClipboard(createdSecret);
    setCopiedMessage(copied ? 'Webhook secret copied to clipboard.' : 'Unable to copy webhook secret.');
  };

  const auditEnabledCount = webhooks.filter((webhook) => webhook.eventTypes.some((eventType) => eventType.startsWith('audit.'))).length;
  const asyncEnabledCount = webhooks.filter((webhook) => webhook.eventTypes.some((eventType) => ASYNC_GATEWAY_PRESET.includes(eventType))).length;

  return (
    <>
      <ResourcePage
        title={t('org.webhooks.title', 'Webhooks')}
        description={t('org.webhooks.description', 'Deliver asynchronous gateway results and audit events to external systems.')}
        tabs={getOrgTabs(t)}
        breadcrumbs={getBreadcrumbs(t)}
        actions={
          <Button variant="contained" startIcon={<AddIcon />} onClick={openCreateDialog}>
            {t('org.webhooks.addWebhook', 'Add Webhook')}
          </Button>
        }
      >
        <Stack spacing={3}>
          <Alert severity="info">
            Webhooks are the outbound integration channel for external workflow systems, audit platforms, and SIEM tooling.
            Pair them with API keys when a partner system needs both synchronous gateway access and asynchronous event delivery.
          </Alert>

          {copiedMessage && (
            <Alert severity="success" onClose={() => setCopiedMessage('')}>
              {copiedMessage}
            </Alert>
          )}

          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <SyncAltIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Async callback endpoints</Typography>
                  </Stack>
                  <Typography variant="h4">{asyncEnabledCount}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Endpoints receiving issuance, verification, and application state changes.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <SecurityIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Audit integrations</Typography>
                  </Stack>
                  <Typography variant="h4">{auditEnabledCount}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Endpoints forwarding audit and compliance activity to external systems.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <AddIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Total webhooks</Typography>
                  </Stack>
                  <Typography variant="h4">{webhooks.length}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Active and inactive endpoints configured for this organization.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {error && (
            <Alert severity="error">{error?.message || String(error)}</Alert>
          )}

          {loading ? (
            <LinearProgress />
          ) : (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>URL</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Events</TableCell>
                    <TableCell>Last delivery</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {webhooks.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        <Box sx={{ py: 5 }}>
                          <Typography variant="subtitle1" gutterBottom>
                            No webhooks configured
                          </Typography>
                          <Typography color="text.secondary">
                            Add a callback endpoint to deliver async results or forward audit events to external tooling.
                          </Typography>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ) : (
                    webhooks.map((webhook) => (
                      <TableRow key={webhook.id} hover>
                        <TableCell>
                          <Typography variant="body2">{webhook.url}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{webhook.description || 'No description'}</Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {webhook.eventTypes.slice(0, 2).map((eventType) => (
                              <Chip key={eventType} label={eventType} size="small" variant="outlined" />
                            ))}
                            {webhook.eventTypes.length > 2 && (
                              <Chip label={`+${webhook.eventTypes.length - 2}`} size="small" />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>{formatDateTime(webhook.lastTriggeredAt)}</TableCell>
                        <TableCell>
                          <Chip label={webhook.enabled ? 'Active' : 'Disabled'} color={webhook.enabled ? 'success' : 'default'} size="small" />
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="Send test callback">
                            <IconButton size="small" onClick={() => handleTest(webhook.id)}>
                              <PlayArrowIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Edit webhook">
                            <IconButton size="small" onClick={() => openEditDialog(webhook)}>
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete webhook">
                            <IconButton size="small" color="error" aria-label="Delete webhook" onClick={() => setPendingDelete(webhook)}>
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
        </Stack>
      </ResourcePage>

      <Dialog open={dialogOpen} onClose={saving ? undefined : resetDialog} maxWidth="md" fullWidth>
        <DialogTitle>{editingWebhook ? 'Edit webhook' : 'Add webhook'}</DialogTitle>
        <DialogContent dividers>
          <Stack spacing={3} sx={{ pt: 1 }}>
            {dialogError && <Alert severity="error">{dialogError}</Alert>}

            <TextField
              autoFocus
              label="Webhook URL"
              placeholder="https://partner.example.com/marty/events"
              value={formState.url}
              onChange={(event) => setFormState((prev) => ({ ...prev, url: event.target.value }))}
              fullWidth
              helperText="Signed POST requests will be delivered to this endpoint."
            />

            <TextField
              label="Description"
              placeholder="Production audit sink"
              value={formState.description}
              onChange={(event) => setFormState((prev) => ({ ...prev, description: event.target.value }))}
              fullWidth
            />

            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Quick presets
              </Typography>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                <Button variant="outlined" onClick={() => applyPreset(ASYNC_GATEWAY_PRESET)}>
                  Gateway async callbacks
                </Button>
                <Button variant="outlined" onClick={() => applyPreset(AUDIT_PRESET)}>
                  External audit feed
                </Button>
              </Stack>
            </Box>

            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Event subscriptions
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                Select the events this receiver should process. Audit events are intended for SIEM, compliance, and external logging systems.
              </Typography>
              <FormGroup>
                {eventCatalog.map((category) => (
                  <Box key={category.name} sx={{ mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ mb: 0.5 }}>{category.name}</Typography>
                    {category.events.map((eventType) => (
                      <FormControlLabel
                        key={eventType.type}
                        control={
                          <Checkbox
                            checked={formState.eventTypes.includes(eventType.type)}
                            onChange={() => toggleEventType(eventType.type)}
                          />
                        }
                        label={
                          <Box>
                            <Typography variant="body2">{eventType.type}</Typography>
                            <Typography variant="caption" color="text.secondary">{eventType.description}</Typography>
                          </Box>
                        }
                      />
                    ))}
                  </Box>
                ))}
              </FormGroup>
            </Box>

            {createdSecret && (
              <Alert severity="success">
                <Typography variant="subtitle2" gutterBottom>
                  Webhook secret
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  Save this now so the receiving system can verify callback signatures.
                </Typography>
                <TextField
                  fullWidth
                  value={createdSecret}
                  InputProps={{
                    readOnly: true,
                    endAdornment: (
                      <IconButton onClick={handleCopySecret}>
                        <ContentCopyIcon />
                      </IconButton>
                    ),
                    sx: { fontFamily: 'monospace' },
                  }}
                />
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={resetDialog}>{createdSecret ? 'Close' : 'Cancel'}</Button>
          {!createdSecret && (
            <Button variant="contained" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving…' : editingWebhook ? 'Update webhook' : 'Create webhook'}
            </Button>
          )}
        </DialogActions>
      </Dialog>

      <ConfirmDeleteDialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        onConfirm={handleDelete}
        title="Delete Webhook"
        itemName={pendingDelete?.description || pendingDelete?.url}
        warning={
          <Alert severity="warning" sx={{ mt: 2 }}>
            External systems will stop receiving asynchronous status updates and audit notifications from this endpoint.
          </Alert>
        }
      />
    </>
  );
}

export default WebhooksPage;
