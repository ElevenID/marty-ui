import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  LinearProgress,
  Paper,
  Stack,
  Tab,
  Tabs,
  Typography,
} from '@mui/material';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BadgeIcon from '@mui/icons-material/WorkspacePremium';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import WarningIcon from '@mui/icons-material/Warning';
import { Link, useParams } from 'react-router-dom';
import { useMemo, useState } from 'react';

import { ResourcePage } from '../../common';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { getCredentialTemplate } from '../../../services/presentationPolicyApi';
import {
  createDeliveryDestination,
  listDeliveryDestinations,
  updateDeliveryDestination,
} from '../../../services/deliveryDestinationsApi';
import {
  getCanvasMirrorHealth,
  listCanvasProgramBindings,
} from '../../../services/canvasIntegrationsApi';

const CANVAS_DESTINATION_ID = 'dd-canvas-credentials-institutional';

const CANVAS_CREDENTIALS_PROJECTION_POLICY = {
  mode: 'public_badge',
  allowed_claims: [
    'achievement',
    'issuer',
    'credentialSubject',
    'credentialStatus',
    'provenance',
  ],
};

function canvasCredentialsDestinationPayload(organizationId) {
  return {
    organization_id: organizationId,
    name: 'Canvas Credentials',
    description: 'Publish a public Open Badge view to Canvas Credentials after ElevenID issuance.',
    provider: 'canvas_credentials',
    mode: 'organization_mirror',
    setup_actor: 'org_admin',
    delivery_target: 'canvas_credentials',
    connector_type: 'canvas_platform',
    requires_consent: true,
    claim_projection_policy: CANVAS_CREDENTIALS_PROJECTION_POLICY,
    setup_requirements: [
      'Canvas Credentials issuer/API access configured by an organization admin',
      'Canvas program binding enabled for Canvas mirror delivery',
    ],
    capabilities: {
      holder_wallet: false,
      org_managed: true,
      post_issuance_publish: true,
      status_sync: true,
      provenance: true,
    },
    is_enabled: true,
  };
}

function formatDate(value) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleDateString();
}

function formatFormat(template = {}) {
  const safeTemplate = template || {};
  return (
    safeTemplate.credential_payload_format
    || safeTemplate.credential_format
    || safeTemplate.format
    || safeTemplate.supported_formats?.[0]
    || 'Unknown'
  );
}

function providerLabel(destination = {}) {
  if (destination.provider === 'canvas_credentials') return 'Canvas Credentials';
  if (destination.mode === 'holder_wallet') return 'Wallet';
  return destination.provider || destination.mode || 'Destination';
}

function destinationIcon(destination = {}) {
  if (destination.provider === 'canvas_credentials') return <SyncAltIcon color="primary" />;
  if (destination.mode === 'holder_wallet') return <WalletIcon color="action" />;
  return <OpenInNewIcon color="action" />;
}

function metadataValue(value) {
  if (value === true) return 'Enabled';
  if (value === false) return 'Disabled';
  return value || 'Not configured';
}

function healthCount(value) {
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}

function healthChipColor(value) {
  return healthCount(value) > 0 ? 'warning' : 'default';
}

function formatTimestamp(value) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function templateMatchesBinding(templateId, binding = {}) {
  return (
    binding.credential_template_id === templateId
    || binding.metadata?.credential_template_id === templateId
    || binding.canvas_credentials?.credential_template_id === templateId
  );
}

function canvasCredentialsConfig(binding = {}) {
  return binding.canvas_credentials || binding.metadata?.canvas_credentials || {};
}

function canvasTokenSource(config = {}) {
  if (config.api_token_secret_id || config.api_token_secret_ref) return 'managed secret';
  if (config.api_token_env) return `env: ${config.api_token_env}`;
  if (config.api_token_file) return 'secret file';
  return 'not configured';
}

function DestinationCard({
  destination,
  canvasBindings,
  mirrorHealth,
  orgCanvasDestination,
  destinationBusy,
  onCreateCanvasDestination,
  onToggleCanvasDestination,
}) {
  const isCanvas = destination.provider === 'canvas_credentials' || destination.id === CANVAS_DESTINATION_ID;
  const destinationEnabled = destination.is_enabled !== false;
  const configured = !isCanvas || (destinationEnabled && canvasBindings.length > 0);
  const projectionMode = destination.claim_projection_policy?.mode || destination.metadata?.projection_mode;
  const alertCount = healthCount(mirrorHealth?.alert_count);
  const failedPublishCount = healthCount(mirrorHealth?.failed_publish_count);
  const syncFailureCount = healthCount(mirrorHealth?.lifecycle_sync_failed_count);

  return (
    <Paper variant="outlined" sx={{ p: 2, borderRadius: 1 }}>
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1.5} alignItems="flex-start" justifyContent="space-between">
          <Stack direction="row" spacing={1.25} alignItems="center">
            {destinationIcon(destination)}
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 800 }}>
                {destination.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {destination.description || providerLabel(destination)}
              </Typography>
            </Box>
          </Stack>
          <Chip
            size="small"
            label={configured ? 'Ready' : 'Setup needed'}
            color={configured ? 'success' : 'warning'}
            icon={configured ? <CheckCircleIcon /> : <WarningIcon />}
          />
        </Stack>

        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Chip size="small" label={providerLabel(destination)} variant="outlined" />
          <Chip size="small" label={destination.setup_actor || 'system'} variant="outlined" />
          <Chip size="small" label={destination.credential_format || 'Any format'} variant="outlined" />
        </Box>

        {isCanvas ? (
          <>
            <Divider />
            <Stack spacing={1}>
              <Typography variant="body2">
                <strong>Projection:</strong> {metadataValue(projectionMode || 'public_badge_provenance')}
              </Typography>
              <Typography variant="body2">
                <strong>Active bindings for this template:</strong> {canvasBindings.length}
              </Typography>
              {canvasBindings.map((binding) => (
                <Box key={binding.id} sx={{ pl: 1, borderLeft: '3px solid', borderColor: 'primary.light' }}>
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>
                    {binding.display_name || binding.canvas_scope?.course_id || binding.id}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Canvas scope: {binding.canvas_scope?.course_id || 'course not set'} / {binding.canvas_scope?.quiz_id || binding.canvas_scope?.assignment_id || 'activity not set'}
                  </Typography>
                  <Box sx={{ mt: 1, display: 'grid', gap: 0.5, gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' } }}>
                    <Typography variant="caption">
                      <strong>Provider:</strong> {metadataValue(canvasCredentialsConfig(binding).provider || 'badgr_api')}
                    </Typography>
                    <Typography variant="caption">
                      <strong>Assertion scope:</strong> {metadataValue(canvasCredentialsConfig(binding).assertion_scope || 'badgeclasses')}
                    </Typography>
                    <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>
                      <strong>Badge class:</strong> {metadataValue(canvasCredentialsConfig(binding).badgeclass_id || canvasCredentialsConfig(binding).canvas_credentials_badgeclass_id)}
                    </Typography>
                    <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>
                      <strong>Issuer:</strong> {metadataValue(canvasCredentialsConfig(binding).issuer_id || canvasCredentialsConfig(binding).canvas_credentials_issuer_id)}
                    </Typography>
                    <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>
                      <strong>API base:</strong> {metadataValue(canvasCredentialsConfig(binding).api_base_url || canvasCredentialsConfig(binding).canvas_credentials_api_base_url)}
                    </Typography>
                    <Typography variant="caption">
                      <strong>Token:</strong> {canvasTokenSource(canvasCredentialsConfig(binding))}
                    </Typography>
                  </Box>
                </Box>
              ))}
              {!canvasBindings.length ? (
                <Typography variant="body2" color="text.secondary">
                  Configure a Canvas program binding to mirror this badge to Canvas Credentials.
                </Typography>
              ) : null}
              {destinationEnabled ? null : (
                <Alert severity="warning">
                  Canvas Credentials is disabled for this organization. Enable the destination before learners can consent to Canvas display.
                </Alert>
              )}
            </Stack>
            <Divider />
            <Stack spacing={1} data-testid="credential-template-canvas-health">
              <Typography variant="body2" sx={{ fontWeight: 700 }}>
                Mirror health
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Chip
                  size="small"
                  label={`Pending: ${healthCount(mirrorHealth?.pending_publish_count)}`}
                  color={healthChipColor(mirrorHealth?.pending_publish_count)}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Failed: ${failedPublishCount}`}
                  color={failedPublishCount > 0 ? 'error' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Delivered: ${healthCount(mirrorHealth?.delivered_count)}`}
                  color={healthCount(mirrorHealth?.delivered_count) > 0 ? 'success' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Sync failures: ${syncFailureCount}`}
                  color={syncFailureCount > 0 ? 'error' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Alerts: ${alertCount}`}
                  color={alertCount > 0 ? 'warning' : 'default'}
                  variant="outlined"
                />
              </Box>
              <Typography variant="caption" color="text.secondary">
                Last successful publish: {formatTimestamp(mirrorHealth?.last_successful_publish_at)}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Last status sync success: {formatTimestamp(mirrorHealth?.last_lifecycle_sync_success_at)}
              </Typography>
              {alertCount > 0 ? (
                <Alert severity={mirrorHealth?.critical_alert_count > 0 ? 'error' : 'warning'}>
                  Canvas mirror drift needs attention. Use Canvas setup to run the automation cycle or retry failed syncs.
                </Alert>
              ) : null}
            </Stack>
            <Box>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {!orgCanvasDestination ? (
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={Boolean(destinationBusy)}
                    onClick={onCreateCanvasDestination}
                  >
                    Add org destination
                  </Button>
                ) : (
                  <Button
                    size="small"
                    variant="outlined"
                    disabled={Boolean(destinationBusy)}
                    onClick={onToggleCanvasDestination}
                  >
                    {orgCanvasDestination.is_enabled === false ? 'Enable destination' : 'Disable destination'}
                  </Button>
                )}
                <Button component={Link} to="/console/org/deploy/canvas" size="small" endIcon={<OpenInNewIcon />}>
                  Manage Canvas platforms
                </Button>
              </Stack>
            </Box>
          </>
        ) : null}
      </Stack>
    </Paper>
  );
}

function CredentialTemplateDetailPage() {
  const { templateId } = useParams();
  const { organizationId } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [destinationBusy, setDestinationBusy] = useState(false);
  const [destinationError, setDestinationError] = useState(null);

  const {
    data: template,
    loading: templateLoading,
    error: templateError,
  } = useAsyncData(() => (templateId ? getCredentialTemplate(templateId) : Promise.resolve(null)), [templateId]);

  const { data: destinationsData = [], reload: reloadDestinations } = useAsyncData(
    () => listDeliveryDestinations({ organizationId, activeOnly: false }).catch(() => []),
    [organizationId],
  );

  const { data: bindingsData = [] } = useAsyncData(
    () => (organizationId ? listCanvasProgramBindings({ organizationId }).catch(() => []) : Promise.resolve([])),
    [organizationId],
  );

  const { data: mirrorHealth = null } = useAsyncData(
    () => (organizationId ? getCanvasMirrorHealth(organizationId).catch(() => null) : Promise.resolve(null)),
    [organizationId],
  );

  const destinations = Array.isArray(destinationsData) ? destinationsData : [];
  const canvasBindings = useMemo(
    () => (Array.isArray(bindingsData) ? bindingsData.filter((binding) => templateMatchesBinding(templateId, binding)) : []),
    [bindingsData, templateId],
  );

  const orgCanvasDestination = destinations.find((destination) => (
    destination.provider === 'canvas_credentials'
    && destination.mode === 'organization_mirror'
    && !destination.is_system
  ));
  const systemCanvasDestination = destinations.find((destination) => (
    destination.id === CANVAS_DESTINATION_ID
    || (destination.provider === 'canvas_credentials' && destination.mode === 'organization_mirror')
  ));
  const canvasDestination = orgCanvasDestination || systemCanvasDestination || null;
  const orderedDestinations = [
    ...(canvasDestination ? [canvasDestination] : []),
    ...destinations.filter((destination) => destination !== canvasDestination),
  ];

  const createCanvasDestination = async () => {
    if (!organizationId) return;
    setDestinationBusy(true);
    setDestinationError(null);
    try {
      await createDeliveryDestination(canvasCredentialsDestinationPayload(organizationId));
      await reloadDestinations();
    } catch (err) {
      setDestinationError(err);
    } finally {
      setDestinationBusy(false);
    }
  };

  const toggleCanvasDestination = async () => {
    if (!orgCanvasDestination) return;
    setDestinationBusy(true);
    setDestinationError(null);
    try {
      await updateDeliveryDestination(orgCanvasDestination.id, {
        is_enabled: orgCanvasDestination.is_enabled === false,
      });
      await reloadDestinations();
    } catch (err) {
      setDestinationError(err);
    } finally {
      setDestinationBusy(false);
    }
  };

  return (
    <ResourcePage
      title={template?.name || 'Credential Template'}
      description="Review credential metadata and delivery destinations for this template."
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Templates', path: '/console/org/templates' },
        { label: 'Credential Templates', path: '/console/org/templates/credentials' },
        { label: template?.name || templateId, path: `/console/org/templates/credentials/${templateId}` },
      ]}
    >
      {templateLoading ? <LinearProgress sx={{ mb: 2 }} /> : null}
      {templateError ? (
        <Alert severity="error" sx={{ mb: 2 }}>
          {templateError?.message || String(templateError)}
        </Alert>
      ) : null}

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={activeTab} onChange={(_event, value) => setActiveTab(value)}>
          <Tab value="overview" label="Overview" />
          <Tab value="destinations" label="Destinations" />
        </Tabs>
      </Box>

      {activeTab === 'overview' ? (
        <Paper variant="outlined" sx={{ p: 3, borderRadius: 1 }}>
          <Stack spacing={2}>
            <Stack direction="row" spacing={1.5} alignItems="center">
              <BadgeIcon color="primary" />
              <Typography variant="h6" sx={{ fontWeight: 800 }}>
                Template overview
              </Typography>
            </Stack>
            <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' } }}>
              <Box>
                <Typography variant="caption" color="text.secondary">Credential Type</Typography>
                <Typography variant="body2">{template?.credential_type || 'Not recorded'}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Format</Typography>
                <Typography variant="body2">{formatFormat(template)}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Status</Typography>
                <Typography variant="body2">{template?.status || 'Not recorded'}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Updated</Typography>
                <Typography variant="body2">{formatDate(template?.updatedAt || template?.updated_at)}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Claims</Typography>
                <Typography variant="body2">{Array.isArray(template?.claims) ? template.claims.length : 0}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Template ID</Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{templateId}</Typography>
              </Box>
            </Box>
          </Stack>
        </Paper>
      ) : (
        <Stack spacing={2}>
          <Alert severity="info">
            Destinations describe where an issued credential can be claimed or mirrored. Canvas Credentials is an organization-managed destination, not a holder wallet.
          </Alert>
          {destinationError ? (
            <Alert severity="error">
              {destinationError?.message || String(destinationError)}
            </Alert>
          ) : null}
          <Stack spacing={2} data-testid="credential-template-destinations">
            {orderedDestinations.map((destination) => (
              <DestinationCard
                key={destination.id}
                destination={destination}
                canvasBindings={destination.provider === 'canvas_credentials' || destination.id === CANVAS_DESTINATION_ID ? canvasBindings : []}
                mirrorHealth={destination.provider === 'canvas_credentials' || destination.id === CANVAS_DESTINATION_ID ? mirrorHealth : null}
                orgCanvasDestination={orgCanvasDestination}
                destinationBusy={destinationBusy}
                onCreateCanvasDestination={createCanvasDestination}
                onToggleCanvasDestination={toggleCanvasDestination}
              />
            ))}
            {!orderedDestinations.length ? (
              <Paper variant="outlined" sx={{ p: 3, borderRadius: 1, textAlign: 'center' }}>
                <AccountTreeIcon color="disabled" />
                <Typography variant="body2" color="text.secondary">
                  No delivery destinations are available for this organization.
                </Typography>
              </Paper>
            ) : null}
          </Stack>
        </Stack>
      )}
    </ResourcePage>
  );
}

export default CredentialTemplateDetailPage;
