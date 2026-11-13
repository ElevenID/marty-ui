import { useBrowserEntry, useIsCurrentBrowserEntry } from '../../../hooks/useBrowserEntry';
/**
 * API Keys Page
 *
 * External integration surface for gateway consumers.
 * API keys authorize synchronous calls; optional paired callbacks handle
 * asynchronous completions and notifications.
 */

import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useLocation } from 'react-router';
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
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { useAuth } from '../../../hooks/useAuth';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createApiKey, listApiKeys, revokeApiKey } from '../../../services/apiKeysApi';
import {
  createWebhookConfiguration as createWebhook,
  getAvailableEventTypes,
  listWebhooks,
} from '../../../services/webhooksApi';
import {
  ASYNC_GATEWAY_EVENT_PRESET,
  flattenWebhookEventCatalog,
} from '../../../services/webhookEvents';

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
    id: 'templates:read',
    label: 'Read credential templates',
    description: 'Read credential template definitions for external integrations.',
  },
  {
    id: 'trust:read',
    label: 'Read trust registry',
    description: 'Query trust registries, issuers, and trust anchors.',
  },
  {
    id: 'wallet:read',
    label: 'Read wallet registry',
    description: 'Read global wallet compatibility data and organization-owned overrides.',
  },
  {
    id: 'wallet:write',
    label: 'Manage wallet registry',
    description: 'Create and maintain organization-owned wallet registry overrides.',
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
  {
    id: 'webhooks:read',
    label: 'Read webhook delivery history',
    description: 'Inspect webhook endpoints, subscriptions, and delivery records.',
  },
  {
    id: 'applications:read',
    label: 'Read applications',
    description: 'Read organization applicant queues and application state.',
  },
  {
    id: 'applications:approve',
    label: 'Approve applications',
    description: 'Approve submitted applications from an external integration.',
  },
  {
    id: 'integrations:read',
    label: 'Read integrations',
    description: 'Read Canvas platforms, bindings, readiness, synchronization jobs, and reviews.',
  },
  {
    id: 'integrations:write',
    label: 'Manage integrations',
    description: 'Configure, authorize, activate, retry, and archive Canvas integrations.',
  },
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
    secret: webhook?.signing_secret || webhook?.secret || '',
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
  try {
    return document.execCommand('copy');
  } finally {
    textArea.remove();
  }
}

function ApiKeysContent({ organizationId, browserEntry }) {
  const { t } = useTranslation('console');
  const { can, isLoading: permissionsLoading } = usePermissions();
  const canCreateKey = !permissionsLoading && can('api-key', 'create');
  const canRevokeKey = !permissionsLoading && can('api-key', 'revoke');
  const canViewCallbacks = !permissionsLoading && can('webhook', 'view');
  const canCreateWebhook = !permissionsLoading && can('webhook', 'create');
  const canCreateCallback = canViewCallbacks && canCreateWebhook;
  const currentPermissions = useRef({ canCreateKey, canCreateCallback });
  currentPermissions.current = { canCreateKey, canCreateCallback };
  const active = useRef(false);
  const dialogGeneration = useRef(0);
  const createPending = useRef(false);
  const startAction = useAsyncActionScope();
  const isCurrentBrowserEntry = useIsCurrentBrowserEntry(browserEntry);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const [callbackValidationError, setCallbackValidationError] = useState('');
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
    callbackEvents: [...ASYNC_GATEWAY_EVENT_PRESET],
  });

  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);

  useLayoutEffect(() => {
    if (typeof window === 'undefined') return undefined;
    // Invalidate pending work before Back can make the original URL current.
    const invalidateAction = () => { startAction(); };
    window.addEventListener('popstate', invalidateAction, true);
    return () => window.removeEventListener('popstate', invalidateAction, true);
  }, [startAction]);

  useLayoutEffect(() => {
    if (!canRevokeKey) setKeyPendingRevoke(null);
  }, [canRevokeKey]);

  const { data, loading, error, reload } = useAsyncData(
    async () => {
      if (!organizationId) return { keys: [], webhooks: [], callbackEventOptions: [] };
      const [keysResult, webhooksResult, eventCatalogResult] = await Promise.allSettled([
        listApiKeys(organizationId),
        canViewCallbacks ? listWebhooks(organizationId) : Promise.resolve([]),
        canViewCallbacks ? getAvailableEventTypes(organizationId) : Promise.resolve(null),
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
        callbackEventOptions: eventCatalogResult.status === 'fulfilled'
          ? flattenWebhookEventCatalog(eventCatalogResult.value?.categories)
          : [],
        eventCatalogError: eventCatalogResult.status === 'rejected'
          ? eventCatalogResult.reason?.message || 'Webhook event types could not be loaded.'
          : null,
      };
    },
    [organizationId, canViewCallbacks],
  );

  const apiKeys = data?.keys || [];
  const webhookLoadError = canViewCallbacks ? data?.webhookError || null : null;
  const callbackEventOptions = canViewCallbacks ? data?.callbackEventOptions || [] : [];
  const eventCatalogError = canViewCallbacks ? data?.eventCatalogError || null : null;
  const summaryPending = !organizationId || loading;
  const summaryUnavailable = Boolean(error);
  const callbackMap = useMemo(() => {
    const map = new Map();
    (canViewCallbacks ? data?.webhooks || [] : []).forEach((webhook) => {
      const keyId = extractAssociatedKeyId(webhook.description);
      if (keyId) {
        map.set(keyId, webhook);
      }
    });
    return map;
  }, [data?.webhooks, canViewCallbacks]);

  const handleScopeToggle = (scopeId) => {
    if (createPending.current || saving || !canCreateKey || !isCurrentBrowserEntry()) return;
    setFormState((prev) => ({
      ...prev,
      scopes: prev.scopes.includes(scopeId)
        ? prev.scopes.filter((scope) => scope !== scopeId)
        : [...prev.scopes, scopeId],
    }));
  };

  const handleCallbackEventToggle = (eventId) => {
    if (createPending.current || saving || !canCreateKey || !isCurrentBrowserEntry()) return;
    setFormState((prev) => ({
      ...prev,
      callbackEvents: prev.callbackEvents.includes(eventId)
        ? prev.callbackEvents.filter((event) => event !== eventId)
        : [...prev.callbackEvents, eventId],
    }));
  };

  const resetDialog = () => {
    if (createPending.current || saving || !isCurrentBrowserEntry()) return;
    dialogGeneration.current += 1;
    setDialogOpen(false);
    setSaving(false);
    setFormError('');
    setCallbackValidationError('');
    setCopiedMessage('');
    setCreatedResult(null);
    setFormState({
      name: '',
      scopes: ['flows:execute'],
      expiresAt: '',
      createCallback: true,
      callbackUrl: '',
      callbackDescription: '',
      callbackEvents: [...ASYNC_GATEWAY_EVENT_PRESET],
    });
  };

  const openCreateDialog = () => {
    if (!canCreateKey || createPending.current || !isCurrentBrowserEntry()) return;
    dialogGeneration.current += 1;
    setCopiedMessage('');
    setFormState((prev) => ({ ...prev, createCallback: canCreateCallback }));
    setDialogOpen(true);
  };

  const updateForm = (updates) => {
    if (createPending.current || saving || !canCreateKey || !isCurrentBrowserEntry()) return;
    setFormState((previous) => ({ ...previous, ...updates }));
    if (updates.createCallback === false) setCallbackValidationError('');
  };

  const handleCreate = async () => {
    if (createPending.current || saving || createdResult || !canCreateKey || !isCurrentBrowserEntry()) return;
    setFormError('');
    setCallbackValidationError('');
    const shouldCreateCallback = canCreateCallback && formState.createCallback;
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

    if (shouldCreateCallback && !formState.callbackUrl.trim()) {
      setCallbackValidationError('Enter a callback URL or turn off callback creation.');
      return;
    }

    if (shouldCreateCallback && formState.callbackEvents.length === 0) {
      setCallbackValidationError('Select at least one callback event.');
      return;
    }

    if (shouldCreateCallback && eventCatalogError) {
      setCallbackValidationError('Webhook event types are unavailable. Retry or turn off callback creation.');
      return;
    }

    if (shouldCreateCallback) {
      const supportedEvents = new Set(callbackEventOptions.map((event) => event.id));
      const unsupportedEvents = formState.callbackEvents.filter((event) => !supportedEvents.has(event));
      if (unsupportedEvents.length > 0) {
        setCallbackValidationError(`Unsupported callback events: ${unsupportedEvents.join(', ')}`);
        return;
      }
    }

    const action = startAction();
    const generation = dialogGeneration.current;
    const isCurrent = () => action.isCurrent() && dialogGeneration.current === generation && isCurrentBrowserEntry();
    createPending.current = true;
    setSaving(true);

    let callbackError = null;

    try {
      const keyResponse = await createApiKey(organizationId, {
        name: formState.name.trim(),
        scopes: formState.scopes,
        expiresAt: formState.expiresAt ? new Date(formState.expiresAt).toISOString() : null,
      }, { isCurrent });
      if (!isCurrent()) return;

      const createdKey = normalizeApiKey(keyResponse);
      let createdWebhook = null;

      if (shouldCreateCallback && (!currentPermissions.current.canCreateKey || !currentPermissions.current.canCreateCallback)) {
        callbackError = 'Callback creation was skipped because your creation permissions are no longer available. You can add a callback later from Webhooks.';
      } else if (shouldCreateCallback) {
        try {
          const webhookResponse = await createWebhook(organizationId, {
            url: formState.callbackUrl.trim(),
            description: buildAssociatedCallbackDescription(
              createdKey.name,
              createdKey.id,
              formState.callbackDescription,
            ),
            eventTypes: formState.callbackEvents,
          }, { isCurrent: () => isCurrent()
            && currentPermissions.current.canCreateKey && currentPermissions.current.canCreateCallback });
          createdWebhook = normalizeWebhook(webhookResponse);
        } catch (errorCreatingWebhook) {
          callbackError = errorCreatingWebhook instanceof Error
            ? errorCreatingWebhook.message
            : String(errorCreatingWebhook);
        }
      }

      if (!isCurrent()) return;
      setCreatedResult({
        apiKey: createdKey,
        webhook: createdWebhook,
        callbackRequested: shouldCreateCallback,
        callbackError,
      });

      await reload();
    } catch (createError) {
      if (isCurrent()) setFormError(createError instanceof Error ? createError.message : String(createError));
    } finally {
      if (isCurrent()) {
        createPending.current = false;
        setSaving(false);
      }
    }
  };

  const handleRevoke = async () => {
    if (!organizationId || !keyPendingRevoke || !canRevokeKey || !isCurrentBrowserEntry()) {
      return;
    }

    await revokeApiKey(organizationId, keyPendingRevoke.id);
    if (!active.current || !isCurrentBrowserEntry()) return;
    setKeyPendingRevoke(null);
    await reload();
  };

  const handleCopy = async (text, label) => {
    if (!isCurrentBrowserEntry()) return;
    const generation = dialogGeneration.current;
    let copied = false;
    try {
      copied = await copyToClipboard(text);
    } catch {
      // Browser clipboard permissions can reject even on an HTTPS origin.
    }
    if (active.current && dialogGeneration.current === generation && isCurrentBrowserEntry()) {
      setCopiedMessage(copied ? `${label} copied to clipboard.` : `Unable to copy ${label.toLowerCase()}.`);
    }
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
          <Button variant="contained" startIcon={<AddIcon />} disabled={!organizationId || loading || Boolean(error) || !canCreateKey || !isCurrentBrowserEntry()} onClick={openCreateDialog}>
            {t('deploy.apiKeysPage.generateKey', 'Create API Key')}
          </Button>
        }
      >
        <Stack spacing={3}>
          {!organizationId && <Alert severity="info">Select an organization to manage API keys.</Alert>}
          <Alert severity="info">
            Use API keys for synchronous gateway calls. Pair each key with a callback endpoint to receive
            asynchronous completions, verification outcomes, and delivery notifications. Forward audit events through
            Webhooks when external SIEM or compliance systems need a real-time feed.
          </Alert>

          {copiedMessage && !dialogOpen && (
            <Alert severity={copiedMessage.startsWith('Unable') ? 'warning' : 'success'} onClose={() => setCopiedMessage('')}>
              {copiedMessage}
            </Alert>
          )}

          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card variant="outlined" sx={{ height: '100%' }}>
                <CardContent>
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
                    <VpnKeyIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Active gateway keys</Typography>
                  </Stack>
                  <Typography variant="h4">{summaryPending ? '—' : summaryUnavailable ? 'Unavailable' : apiKeys.filter((key) => key.enabled).length}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Keys currently usable by partner systems and services.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card variant="outlined" sx={{ height: '100%' }}>
                <CardContent>
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
                    <NotificationsActiveIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Associated callbacks</Typography>
                  </Stack>
                  <Typography variant="h4">{summaryPending ? '—' : summaryUnavailable || webhookLoadError || !canViewCallbacks ? 'Unavailable' : callbackMap.size}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Webhook endpoints linked to API-key provisioning flows.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card variant="outlined" sx={{ height: '100%' }}>
                <CardContent>
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
                    <LinkIcon color="primary" fontSize="small" />
                    <Typography variant="subtitle2">Audit-capable callbacks</Typography>
                  </Stack>
                  <Typography variant="h4">
                    {summaryPending ? '—' : summaryUnavailable || webhookLoadError || !canViewCallbacks
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
            <Alert severity="error" action={<Button color="inherit" onClick={reload}>Retry</Button>}>
              {error?.message || String(error)}
            </Alert>
          )}

          {!permissionsLoading && !canViewCallbacks && (
            <Alert severity="info">
              Webhook viewing permission is required to view callback status and event types.
            </Alert>
          )}

          {webhookLoadError && (
            <Alert severity="warning">
              Callback status could not be loaded: {webhookLoadError}
            </Alert>
          )}

          {loading ? (
            <LinearProgress />
          ) : !error && organizationId ? (
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
                            <Typography variant="body2" sx={{ fontWeight: 600 }}>{apiKey.name}</Typography>
                            {apiKey.description && (
                              <Typography variant="caption" color="text.secondary">{apiKey.description}</Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                {apiKey.maskedKey || apiKey.keyPrefix || 'Unavailable'}
                              </Typography>
                              {!!apiKey.fullKey && (
                                <Tooltip title="Copy full key">
                                  <IconButton size="small" aria-label="Copy API key" onClick={() => handleCopy(apiKey.fullKey, 'API key')}>
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
                            {webhookLoadError || !canViewCallbacks ? (
                              <Typography variant="body2" color="text.secondary">Unavailable</Typography>
                            ) : callback ? (
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
                                  disabled={!apiKey.enabled || !canRevokeKey}
                                  onClick={() => { if (canRevokeKey) setKeyPendingRevoke(apiKey); }}
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
          ) : null}
        </Stack>
      </ResourcePage>
      <Dialog open={dialogOpen} onClose={saving ? undefined : resetDialog} maxWidth="md" fullWidth>
        <DialogTitle>{createdResult ? 'Integration provisioned' : 'Create API key'}</DialogTitle>
        <DialogContent dividers>
          {createdResult ? (
            <Stack spacing={2}>
              {copiedMessage && (
                <Alert severity={copiedMessage.startsWith('Unable') ? 'warning' : 'success'} onClose={() => setCopiedMessage('')}>
                  {copiedMessage}
                </Alert>
              )}
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
                helperText="Save this key now. Depending on the backend response, it may not be shown again."
                slotProps={{
                  input: {
                    readOnly: true,
                    endAdornment: (
                      <IconButton aria-label="Copy API key" disabled={!createdResult.apiKey.fullKey} onClick={() => handleCopy(createdResult.apiKey.fullKey, 'API key')}>
                        <ContentCopyIcon />
                      </IconButton>
                    ),
                    sx: { fontFamily: 'monospace' },
                  }
                }}
              />

              {createdResult.webhook && (
                <>
                  <TextField
                    label="Callback URL"
                    value={createdResult.webhook.url}
                    fullWidth
                    slotProps={{
                      input: { readOnly: true }
                    }}
                  />
                  {createdResult.webhook.secret && (
                    <TextField
                      label="Webhook secret"
                      value={createdResult.webhook.secret}
                      fullWidth
                      helperText="Store this secret in the receiving system to verify callback signatures."
                      slotProps={{
                        input: {
                          readOnly: true,
                          endAdornment: (
                            <IconButton aria-label="Copy webhook secret" onClick={() => handleCopy(createdResult.webhook.secret, 'Webhook secret')}>
                              <ContentCopyIcon />
                            </IconButton>
                          ),
                          sx: { fontFamily: 'monospace' },
                        }
                      }}
                    />
                  )}
                </>
              )}
            </Stack>
          ) : (
            <Stack component="fieldset" disabled={saving || !canCreateKey || !isCurrentBrowserEntry()} aria-label="API key settings" spacing={3} sx={{ p: 0, pt: 1, m: 0, border: 0, minWidth: 0 }}>
              {(formError || callbackValidationError) && <Alert severity="error">{formError || callbackValidationError}</Alert>}
              {!canCreateKey && <Alert severity="info">{permissionsLoading ? 'Checking your permissions…' : 'You do not have permission to create API keys in this organization.'}</Alert>}

              <TextField
                autoFocus
                label="Key name"
                placeholder="Production issuer integration"
                value={formState.name}
                onChange={(event) => updateForm({ name: event.target.value })}
                fullWidth
              />

              <TextField
                label="Expiration"
                type="datetime-local"
                value={formState.expiresAt}
                onChange={(event) => updateForm({ expiresAt: event.target.value })}
                fullWidth
                helperText="Optional expiry for partner credentials or temporary environments."
                slotProps={{
                  inputLabel: { shrink: true }
                }}
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
                      checked={canCreateCallback && formState.createCallback}
                      disabled={!canCreateCallback}
                      onChange={(event) => updateForm({ createCallback: event.target.checked })}
                    />
                  }
                  label="Provision associated callback"
                />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  {canCreateCallback
                    ? 'Recommended for external systems that need asynchronous status updates, completion notices, or audit forwarding.'
                    : !canCreateWebhook
                      ? 'Creating an associated callback requires webhook creation permission.'
                      : 'Creating an associated callback requires webhook viewing permission to load event types.'}
                </Typography>
              </Box>

              {canCreateCallback && formState.createCallback && (
                <Stack spacing={2}>
                  <TextField
                    label="Callback URL"
                    placeholder="https://partner.example.com/marty/callbacks"
                    value={formState.callbackUrl}
                    onChange={(event) => updateForm({ callbackUrl: event.target.value })}
                    fullWidth
                  />
                  <TextField
                    label="Callback description"
                    placeholder="Operations callback for partner orchestration"
                    value={formState.callbackDescription}
                    onChange={(event) => updateForm({ callbackDescription: event.target.value })}
                    fullWidth
                  />
                  <Box>
                    <Typography variant="subtitle2" gutterBottom>
                      Callback event subscriptions
                    </Typography>
                    {eventCatalogError && (
                      <Alert severity="warning" sx={{ mb: 1 }}>
                        Webhook event types could not be loaded. Retry the page or turn off callback creation.
                      </Alert>
                    )}
                    <FormGroup>
                      {callbackEventOptions.map((eventOption) => (
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
            <Button onClick={resetDialog} disabled={saving}>Done</Button>
          ) : (
            <>
              <Button onClick={resetDialog} disabled={saving}>Cancel</Button>
              <Button variant="contained" onClick={handleCreate} disabled={saving || !canCreateKey || !isCurrentBrowserEntry()}>
                {saving ? 'Creating…' : 'Create integration key'}
              </Button>
            </>
          )}
        </DialogActions>
      </Dialog>
      <ConfirmDeleteDialog
        open={Boolean(keyPendingRevoke) && canRevokeKey}
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

export default function ApiKeysPage() {
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const location = useLocation();
  const browserEntry = useBrowserEntry(location);
  const principalId = isAuthenticated ? user?.user_id || user?.sub || user?.id || 'unknown-user' : 'signed-out';
  return <ApiKeysContent key={JSON.stringify([activeOrgId, principalId, location.key,
    location.pathname, location.search, location.hash, browserEntry.generation])}
    organizationId={activeOrgId} browserEntry={browserEntry} />;
}
