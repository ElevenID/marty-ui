/**
 * API Keys Page
 *
 * External integration surface for gateway consumers.
 * API keys authorize synchronous calls; optional paired callbacks handle
 * asynchronous completions and notifications.
 */

import { useMemo, useState } from 'react';
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
  Divider,
  FormControlLabel,
  FormGroup,
  Grid,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  Switch,
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
import LinkIcon from '@mui/icons-material/Link';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import NotificationsActiveIcon from '@mui/icons-material/NotificationsActive';
import DeleteIcon from '@mui/icons-material/Delete';

import { ResourcePage } from '../../common';
import ConfirmDeleteDialog from '../../common/ConfirmDeleteDialog';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createApiKey, listApiKeys, revokeApiKey } from '../../../services/apiKeysApi';
import { createWebhook, listWebhooks } from '../../../services/webhooksApi';

const API_KEY_SCOPES = [
  {
    id: 'credentials:read',
    label: 'Read credentials',
    description: 'Read issued credential and verification result data.',
  },
  {
    id: 'credentials:issue',
    label: 'Issue credentials',
    description: 'Trigger issuance and manage credential lifecycle operations.',
  },
  {
    id: 'flows:execute',
    label: 'Execute flows',
    description: 'Start issuance and verification flows for external integrations.',
  },
  {
    id: 'trust:read',
    label: 'Read trust registry',
    description: 'Query trust registries, issuers, and trust anchors.',
  },
  {
    id: 'credentials:revoke',
    label: 'Manage revocation',
    description: 'Revoke or update credential status from external systems.',
  },
  {
    id: 'webhooks:write',
    label: 'Manage webhooks',
    description: 'Provision and maintain callback endpoints programmatically.',
  },
];

const DEFAULT_CALLBACK_EVENTS = [
  'application.submitted',
  'application.approved',
  'application.rejected',
  'credential.issued',
  'credential.revoked',
  'verification.completed',
  'verification.failed',
];

const CALLBACK_EVENT_OPTIONS = [
  { id: 'application.submitted', label: 'Application submitted' },
  { id: 'application.approved', label: 'Application approved' },
  { id: 'application.rejected', label: 'Application rejected' },
  { id: 'credential.issued', label: 'Credential issued' },
  { id: 'credential.revoked', label: 'Credential revoked' },
  { id: 'verification.completed', label: 'Verification completed' },
  { id: 'verification.failed', label: 'Verification failed' },
  { id: 'audit.configuration_changed', label: 'Audit configuration changed' },
  { id: 'audit.security_event', label: 'Audit security event' },
];

const CALLBACK_TAG_PATTERN = /\[api-key:([^\]]+)\]/i;

const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: t('org.tabs.apiKeys', 'API Keys'), path: '/console/org/api-keys' },
  { label: t('org.tabs.webhooks'), path: '/console/org/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console', 'Console'), path: '/console' },
  { label: t('org.breadcrumbs.org', 'Org'), path: '/console/org' },
  { label: t('org.tabs.apiKeys', 'API Keys'), path: '/console/org/api-keys' },
];

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

function normalizeApiKey(apiKey) {
  const scopes = Array.isArray(apiKey?.scopes) ? apiKey.scopes : [];
  const keyPrefix = apiKey?.keyPrefix || apiKey?.key_prefix || apiKey?.masked_key || '';
  const enabled = apiKey?.enabled ?? apiKey?.is_active ?? apiKey?.status !== 'revoked';
  const status = apiKey?.status || (enabled ? 'active' : 'revoked');

  return {
    id: apiKey?.id || '',
    name: apiKey?.name || 'Unnamed key',
    description: apiKey?.description || '',
    scopes,
    keyPrefix,
    maskedKey: apiKey?.masked_key || keyPrefix,
    status,
    enabled,
    createdAt: apiKey?.createdAt || apiKey?.created_at || null,
    updatedAt: apiKey?.updatedAt || apiKey?.updated_at || null,
    lastUsedAt: apiKey?.lastUsedAt || apiKey?.last_used_at || apiKey?.lastUsed || apiKey?.last_used || null,
    expiresAt: apiKey?.expiresAt || apiKey?.expires_at || null,
    fullKey: apiKey?.fullKey || apiKey?.full_key || apiKey?.key || '',
  };
}

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
    secret: webhook?.secret || '',
  };
}

function extractAssociatedKeyId(description = '') {
  const match = description.match(CALLBACK_TAG_PATTERN);
  return match ? match[1] : null;
}

function buildAssociatedCallbackDescription(name, keyId, description) {
  const base = description?.trim() || `Callback for ${name}`;
  return `${base} [api-key:${keyId}]`;
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

function ApiKeysPage() {
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId || authOrganizationId;
  const [dialogOpen, setDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const [copiedMessage, setCopiedMessage] = useState('');
  const [createdResult, setCreatedResult] = useState(null);
  const [keyPendingRevoke, setKeyPendingRevoke] = useState(null);
  const [formState, setFormState] = useState({
    name: '',
    scopes: ['flows:execute'],
    expiresAt: '',
    createCallback: true,
    callbackUrl: '',
    callbackDescription: '',
    callbackEvents: [...DEFAULT_CALLBACK_EVENTS],
  });

  const { data, loading, error, reload } = useAsyncData(
    async () => {
      const [keysResult, webhooksResult] = await Promise.allSettled([
        listApiKeys(organizationId),
        listWebhooks(organizationId),
      ]);

      if (keysResult.status === 'rejected') {
        throw keysResult.reason;
      }

      return {
        keys: (keysResult.value || []).map(normalizeApiKey),
        webhooks: webhooksResult.status === 'fulfilled'
          ? (webhooksResult.value || []).map(normalizeWebhook)
          : [],
        webhookError: webhooksResult.status === 'rejected'
          ? webhooksResult.reason?.message || 'Webhook callback status could not be loaded.'
          : null,
      };
    },
    [organizationId],
  );

  const apiKeys = data?.keys || [];
  const webhookLoadError = data?.webhookError || null;
  const callbackMap = useMemo(() => {
    const map = new Map();
    (data?.webhooks || []).forEach((webhook) => {
      const keyId = extractAssociatedKeyId(webhook.description);
      if (keyId) {
        map.set(keyId, webhook);
      }
    });
    return map;
  }, [data?.webhooks]);

  const handleScopeToggle = (scopeId) => {
    setFormState((prev) => ({
      ...prev,
      scopes: prev.scopes.includes(scopeId)
        ? prev.scopes.filter((scope) => scope !== scopeId)
        : [...prev.scopes, scopeId],
    }));
  };

  const handleCallbackEventToggle = (eventId) => {
    setFormState((prev) => ({
      ...prev,
      callbackEvents: prev.callbackEvents.includes(eventId)
        ? prev.callbackEvents.filter((event) => event !== eventId)
        : [...prev.callbackEvents, eventId],
    }));
  };

  const resetDialog = () => {
    setDialogOpen(false);
    setSaving(false);
    setFormError('');
    setCreatedResult(null);
    setFormState({
      name: '',
      scopes: ['flows:execute'],
      expiresAt: '',
      createCallback: true,
      callbackUrl: '',
      callbackDescription: '',
      callbackEvents: [...DEFAULT_CALLBACK_EVENTS],
    });
  };

  const handleCreate = async () => {
    if (!organizationId) {
      setFormError('No active organization selected.');
      return;
    }

    if (!formState.name.trim()) {
      setFormError('Enter a name for the API key.');
      return;
    }

    if (formState.scopes.length === 0) {
      setFormError('Select at least one scope for this external integration.');
      return;
    }

    if (formState.createCallback && !formState.callbackUrl.trim()) {
      setFormError('Enter a callback URL or turn off callback creation.');
      return;
    }

    if (formState.createCallback && formState.callbackEvents.length === 0) {
      setFormError('Select at least one callback event.');
      return;
    }

    setSaving(true);
    setFormError('');

    let callbackError = null;

    try {
      const keyResponse = await createApiKey(organizationId, {
        name: formState.name.trim(),
        scopes: formState.scopes,
        expiresAt: formState.expiresAt ? new Date(formState.expiresAt).toISOString() : null,
      });

      const createdKey = normalizeApiKey(keyResponse);
      let createdWebhook = null;

      if (formState.createCallback) {
        try {
          const webhookResponse = await createWebhook(organizationId, {
            url: formState.callbackUrl.trim(),
            description: buildAssociatedCallbackDescription(
              createdKey.name,
              createdKey.id,
              formState.callbackDescription,
            ),
            eventTypes: formState.callbackEvents,
          });
          createdWebhook = normalizeWebhook(webhookResponse);
        } catch (errorCreatingWebhook) {
          callbackError = errorCreatingWebhook instanceof Error
            ? errorCreatingWebhook.message
            : String(errorCreatingWebhook);
        }
      }

      setCreatedResult({
        apiKey: createdKey,
        webhook: createdWebhook,
        callbackRequested: formState.createCallback,
        callbackError,
      });

      await reload();
    } catch (createError) {
      setFormError(createError instanceof Error ? createError.message : String(createError));
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async () => {
    if (!organizationId || !keyPendingRevoke) {
      return;
    }

    await revokeApiKey(organizationId, keyPendingRevoke.id);
    setKeyPendingRevoke(null);
    await reload();
  };

  const handleCopy = async (text, label) => {
    const copied = await copyToClipboard(text);
    setCopiedMessage(copied ? `${label} copied to clipboard.` : `Unable to copy ${label.toLowerCase()}.`);
  };

  return (
    <>
      <ResourcePage
        title={t('deploy.apiKeys')}
        description={t(
          'deploy.apiKeysDescription',
          'Provision external gateway clients and pair them with callbacks for asynchronous results.',
        )}
        tabs={getOrgTabs(t)}
        breadcrumbs={getBreadcrumbs(t)}
        actions={
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDialogOpen(true)}>
            {t('deploy.apiKeysPage.generateKey', 'Create API Key')}
          </Button>
        }
      >
        <Stack spacing={3}>
          <Alert severity="info">
            Use API keys for synchronous gateway calls. Pair each key with a callback endpoint to receive
            asynchronous completions, verification outcomes, and delivery notifications. Forward audit events through
            Webhooks when external SIEM or compliance systems need a real-time feed.
          </Alert>

          {copiedMessage && (
            <Alert severity={copiedMessage.startsWith('Unable') ? 'warning' : 'success'} onClose={() => setCopiedMessage('')}>
              {copiedMessage}
            </Alert>
          )}

          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <VpnKeyIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Active gateway keys</Typography>
                  </Stack>
                  <Typography variant="h4">{apiKeys.filter((key) => key.enabled).length}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Keys currently usable by partner systems and services.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <NotificationsActiveIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Associated callbacks</Typography>
                  </Stack>
                  <Typography variant="h4">{webhookLoadError ? 'Unavailable' : callbackMap.size}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Webhook endpoints linked to API-key provisioning flows.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <LinkIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Audit-capable callbacks</Typography>
                  </Stack>
                  <Typography variant="h4">
                    {webhookLoadError
                      ? 'Unavailable'
                      : Array.from(callbackMap.values()).filter((webhook) => webhook.eventTypes.some((eventType) => eventType.startsWith('audit.'))).length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Callbacks prepared to forward audit or compliance activity.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {error && (
            <Alert severity="error">
              {error?.message || String(error)}
            </Alert>
          )}

          {webhookLoadError && (
            <Alert severity="warning">
              Callback status could not be loaded: {webhookLoadError}
            </Alert>
          )}

          {loading ? (
            <LinearProgress />
          ) : (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Key</TableCell>
                    <TableCell>Scopes</TableCell>
                    <TableCell>Associated callback</TableCell>
                    <TableCell>Last used</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {apiKeys.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <Box sx={{ py: 5 }}>
                          <Typography variant="subtitle1" gutterBottom>
                            No API keys configured
                          </Typography>
                          <Typography color="text.secondary">
                            Create a key for each external system that calls the gateway and optionally provision a paired callback.
                          </Typography>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ) : (
                    apiKeys.map((apiKey) => {
                      const callback = callbackMap.get(apiKey.id);
                      return (
                        <TableRow key={apiKey.id} hover>
                          <TableCell>
                            <Typography variant="body2" fontWeight={600}>{apiKey.name}</Typography>
                            {apiKey.description && (
                              <Typography variant="caption" color="text.secondary">{apiKey.description}</Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                {apiKey.maskedKey || apiKey.keyPrefix || 'Unavailable'}
                              </Typography>
                              {!!apiKey.fullKey && (
                                <Tooltip title="Copy full key">
                                  <IconButton size="small" onClick={() => handleCopy(apiKey.fullKey, 'API key')}>
                                    <ContentCopyIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                              )}
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                              {apiKey.scopes.length === 0 ? (
                                <Typography variant="body2" color="text.secondary">No scopes assigned</Typography>
                              ) : (
                                apiKey.scopes.slice(0, 2).map((scope) => (
                                  <Chip key={scope} label={scope} size="small" variant="outlined" />
                                ))
                              )}
                              {apiKey.scopes.length > 2 && (
                                <Chip label={`+${apiKey.scopes.length - 2}`} size="small" />
                              )}
                            </Box>
                          </TableCell>
                          <TableCell>
                            {callback ? (
                              <Stack spacing={0.5}>
                                <Typography variant="body2">{callback.url}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {callback.eventTypes.length} subscribed event{callback.eventTypes.length === 1 ? '' : 's'}
                                </Typography>
                              </Stack>
                            ) : (
                              <Typography variant="body2" color="text.secondary">No paired callback</Typography>
                            )}
                          </TableCell>
                          <TableCell>{formatDateTime(apiKey.lastUsedAt)}</TableCell>
                          <TableCell>
                            <Chip
                              label={apiKey.enabled ? 'Active' : 'Revoked'}
                              color={apiKey.enabled ? 'success' : 'default'}
                              size="small"
                            />
                          </TableCell>
                          <TableCell align="right">
                            <Tooltip title="Revoke key">
                              <span>
                                <IconButton
                                  size="small"
                                  color="error"
                                  aria-label="Revoke key"
                                  disabled={!apiKey.enabled}
                                  onClick={() => setKeyPendingRevoke(apiKey)}
                                >
                                  <DeleteIcon fontSize="small" />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Stack>
      </ResourcePage>

      <Dialog open={dialogOpen} onClose={saving ? undefined : resetDialog} maxWidth="md" fullWidth>
        <DialogTitle>{createdResult ? 'Integration provisioned' : 'Create API key'}</DialogTitle>
        <DialogContent dividers>
          {createdResult ? (
            <Stack spacing={2}>
              <Alert severity={createdResult.callbackError ? 'warning' : 'success'}>
                API key created successfully.
                {createdResult.callbackError
                  ? ` Callback creation failed: ${createdResult.callbackError}`
                  : createdResult.webhook
                    ? ' Callback endpoint provisioned for asynchronous events.'
                    : createdResult.callbackRequested
                      ? ' Callback endpoint was not provisioned. You can add one later from Webhooks.'
                      : ' No callback endpoint was provisioned.'}
              </Alert>

              <TextField
                label="API key"
                value={createdResult.apiKey.fullKey || createdResult.apiKey.maskedKey || createdResult.apiKey.keyPrefix}
                fullWidth
                InputProps={{
                  readOnly: true,
                  endAdornment: (
                    <IconButton onClick={() => handleCopy(createdResult.apiKey.fullKey, 'API key')}>
                      <ContentCopyIcon />
                    </IconButton>
                  ),
                  sx: { fontFamily: 'monospace' },
                }}
                helperText="Save this key now. Depending on the backend response, it may not be shown again."
              />

              {createdResult.webhook && (
                <>
                  <TextField
                    label="Callback URL"
                    value={createdResult.webhook.url}
                    fullWidth
                    InputProps={{ readOnly: true }}
                  />
                  {createdResult.webhook.secret && (
                    <TextField
                      label="Webhook secret"
                      value={createdResult.webhook.secret}
                      fullWidth
                      InputProps={{
                        readOnly: true,
                        endAdornment: (
                          <IconButton onClick={() => handleCopy(createdResult.webhook.secret, 'Webhook secret')}>
                            <ContentCopyIcon />
                          </IconButton>
                        ),
                        sx: { fontFamily: 'monospace' },
                      }}
                      helperText="Store this secret in the receiving system to verify callback signatures."
                    />
                  )}
                </>
              )}
            </Stack>
          ) : (
            <Stack spacing={3} sx={{ pt: 1 }}>
              {formError && <Alert severity="error">{formError}</Alert>}

              <TextField
                autoFocus
                label="Key name"
                placeholder="Production issuer integration"
                value={formState.name}
                onChange={(event) => setFormState((prev) => ({ ...prev, name: event.target.value }))}
                fullWidth
              />

              <TextField
                label="Expiration"
                type="datetime-local"
                value={formState.expiresAt}
                onChange={(event) => setFormState((prev) => ({ ...prev, expiresAt: event.target.value }))}
                InputLabelProps={{ shrink: true }}
                fullWidth
                helperText="Optional expiry for partner credentials or temporary environments."
              />

              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Scopes
                </Typography>
                <FormGroup>
                  {API_KEY_SCOPES.map((scope) => (
                    <FormControlLabel
                      key={scope.id}
                      control={
                        <Checkbox
                          checked={formState.scopes.includes(scope.id)}
                          onChange={() => handleScopeToggle(scope.id)}
                        />
                      }
                      label={
                        <Box>
                          <Typography variant="body2">{scope.label}</Typography>
                          <Typography variant="caption" color="text.secondary">{scope.description}</Typography>
                        </Box>
                      }
                    />
                  ))}
                </FormGroup>
              </Box>

              <Divider />

              <Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={formState.createCallback}
                      onChange={(event) => setFormState((prev) => ({ ...prev, createCallback: event.target.checked }))}
                    />
                  }
                  label="Provision associated callback"
                />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Recommended for external systems that need asynchronous status updates, completion notices, or audit forwarding.
                </Typography>
              </Box>

              {formState.createCallback && (
                <Stack spacing={2}>
                  <TextField
                    label="Callback URL"
                    placeholder="https://partner.example.com/marty/callbacks"
                    value={formState.callbackUrl}
                    onChange={(event) => setFormState((prev) => ({ ...prev, callbackUrl: event.target.value }))}
                    fullWidth
                  />
                  <TextField
                    label="Callback description"
                    placeholder="Operations callback for partner orchestration"
                    value={formState.callbackDescription}
                    onChange={(event) => setFormState((prev) => ({ ...prev, callbackDescription: event.target.value }))}
                    fullWidth
                  />
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      Callback event subscriptions
                    </Typography>
                    <FormGroup>
                      {CALLBACK_EVENT_OPTIONS.map((eventOption) => (
                        <FormControlLabel
                          key={eventOption.id}
                          control={
                            <Checkbox
                              checked={formState.callbackEvents.includes(eventOption.id)}
                              onChange={() => handleCallbackEventToggle(eventOption.id)}
                            />
                          }
                          label={eventOption.label}
                        />
                      ))}
                    </FormGroup>
                  </Box>
                </Stack>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          {createdResult ? (
            <Button onClick={resetDialog}>Done</Button>
          ) : (
            <>
              <Button onClick={resetDialog} disabled={saving}>Cancel</Button>
              <Button variant="contained" onClick={handleCreate} disabled={saving}>
                {saving ? 'Creating…' : 'Create integration key'}
              </Button>
            </>
          )}
        </DialogActions>
      </Dialog>

      <ConfirmDeleteDialog
        open={Boolean(keyPendingRevoke)}
        onClose={() => setKeyPendingRevoke(null)}
        onConfirm={handleRevoke}
        title="Revoke API Key"
        itemName={keyPendingRevoke?.name}
        confirmLabel="Revoke"
        warning={
          <Alert severity="warning" sx={{ mt: 2 }}>
            External callers using this key will lose access immediately. Associated callbacks are not deleted automatically.
          </Alert>
        }
      />
    </>
  );
}

export default ApiKeysPage;
