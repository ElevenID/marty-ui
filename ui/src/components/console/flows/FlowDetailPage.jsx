/**
 * Flow Detail Page
 * 
 * THE CENTERPIECE: This page represents the applicant-facing product.
 * If an admin understands this page, they understand ElevenID LLC.
 * 
 * Enforces the mental model: Applicants apply to Flows, not Templates.
 */

import { useLayoutEffect, useRef, useState } from 'react';
import { useLocation, useParams, useNavigate, Link as RouterLink } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { getFlow, publishFlow, testFlow, validateFlow } from '../../../services/flowsApi';
import { publicEntryHref } from '../../../application/routing/publicEntry';
import {
  Box,
  Paper,
  Typography,
  Button,
  Chip,
  IconButton,
  Divider,
  Grid,
  Card,
  CardContent,
  Alert,
  Stepper,
  Step,
  StepLabel,
  TextField,
  InputAdornment,
  Tooltip,
  CircularProgress,
  Stack,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import PreviewIcon from '@mui/icons-material/Preview';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import SmartphoneIcon from '@mui/icons-material/Smartphone';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RuleIcon from '@mui/icons-material/Rule';
import ScienceIcon from '@mui/icons-material/Science';

import { ResourcePage } from '../../common';

const getBreadcrumbs = (t) => [
  { label: t('flows.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: t('flows.flowDefinitions'), path: '/console/org/flows/definitions' },
  { label: 'Flow Detail', path: '' },
];

/**
 * Applicant Journey Timeline - THE MOST IMPORTANT SECTION
 * Makes the end-to-end path undeniable
 */
function ApplicantJourney({ flow }) {
  const steps = flow?.resolved_steps || [];

  return (
    <Card elevation={0} sx={{ bgcolor: 'primary.50', border: 1, borderColor: 'primary.100' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          Resolved flow sequence
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {flow.flow_type === 'custom' ? flow.extension?.extension_uri : flow.flow_type}
        </Typography>
        
        <Box sx={{ mt: 3 }}>
          <Stepper activeStep={-1} orientation="vertical">
            {steps.map((stepName) => (
              <Step key={stepName}>
                <StepLabel
                  StepIconProps={{
                    sx: {
                      color: 'primary.main',
                      '&.Mui-active': { color: 'primary.main' },
                    },
                  }}
                >
                  <Typography variant="body2">{stepName.replace(/_/g, ' ')}</Typography>
                </StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>
      </CardContent>
    </Card>
  );
}

/**
 * Live Entry Points - Share Block
 * Reinforces that THIS is what gets shared
 */
function EntryPoints({ publicUrl, onCopy, copying }) {
  const { t } = useTranslation('console');
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          {t('flows.flowDetail.entryPoints.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
          {t('flows.flowDetail.entryPoints.description')}
        </Typography>

        {/* Application URL */}
        <Typography variant="subtitle2" gutterBottom>
          {t('flows.flowDetail.entryPoints.applicationUrlLabel')}
        </Typography>
        <TextField
          fullWidth
          value={publicUrl || t('flows.flowDetail.entryPoints.linkUnavailable')}
          disabled={!publicUrl}
          size="small"
          sx={{ mb: 3 }}
          slotProps={{
            input: {
              readOnly: true,
              endAdornment: publicUrl && (
                <InputAdornment position="end">
                  <Tooltip title={t('flows.flowDetail.entryPoints.copyUrlTooltip')}>
                    <IconButton onClick={onCopy} disabled={copying} edge="end" size="small">
                      <ContentCopyIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('flows.flowDetail.entryPoints.openInNewTabTooltip')}>
                    <IconButton onClick={() => window.open(publicUrl, '_blank', 'noopener,noreferrer')} edge="end" size="small">
                      <OpenInNewIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </InputAdornment>
              ),
            }
          }}
        />

        {/* QR Code */}
        <Typography variant="subtitle2" gutterBottom>
          {t('flows.flowDetail.entryPoints.qrCodeLabel')}
        </Typography>
        {publicUrl ? (
          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              p: 3,
              border: 1,
              borderColor: 'divider',
              borderRadius: 1,
              bgcolor: 'background.default',
            }}
          >
            <QrCode2Icon sx={{ fontSize: 120, color: 'primary.main', mb: 2 }} />
            <Button
              variant="outlined"
              startIcon={<QrCode2Icon />}
              size="small"
              disabled
              title={t('flows.flowDetail.entryPoints.qrDownloadUnavailable')}
            >
              {t('flows.flowDetail.entryPoints.downloadQrButton')}
            </Button>
          </Box>
        ) : (
          <Alert severity="info" sx={{ mt: 1 }}>
            {t('flows.flowDetail.entryPoints.qrUnavailable')}
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Flow Configuration Summary - Read-Only
 * Shows how the flow is wired without editing chaos
 */
function ConfigurationSummary({ flow }) {
  const { t } = useTranslation('console');
  const notAvailable = t('flows.flowDetail.configuration.notAvailable');
  const optionalPath = (basePath, id) => (id ? `${basePath}/${id}` : null);
  const approvalMode = flow?.approval_strategy || notAvailable;
  const config = [
    {
      label: t('flows.flowDetail.configuration.credentialTemplateLabel'),
      value: flow?.credential_template_name || flow?.credential_template_id || notAvailable,
      path: optionalPath('/console/org/templates/credentials', flow?.credential_template_id),
      icon: DescriptionIcon,
    },
    {
      label: t('flows.flowDetail.configuration.applicationRulesLabel'),
      value: flow?.application_rules || flow?.application_template_id || notAvailable,
      path: optionalPath('/console/org/templates/applications', flow?.application_template_id),
      icon: PolicyIcon,
    },
    {
      label: t('flows.flowDetail.configuration.complianceProfileLabel'),
      value: flow?.compliance_profile || flow?.compliance_profile_id || notAvailable,
      path: optionalPath('/console/org/policies/compliance', flow?.compliance_profile_id),
      icon: VerifiedUserIcon,
    },
    {
      label: t('flows.flowDetail.configuration.approvalModeLabel'),
      value: approvalMode,
      icon: CheckCircleIcon,
    },
    {
      label: 'Presentation policy',
      value: flow?.presentation_policy_id || notAvailable,
      path: optionalPath('/console/org/policies/presentation', flow?.presentation_policy_id),
      icon: PolicyIcon,
    },
    {
      label: 'Delivery destination',
      value: flow?.delivery_destination_profile_id || notAvailable,
      icon: SmartphoneIcon,
    },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          {t('flows.flowDetail.configuration.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 2 }}>
          {t('flows.flowDetail.configuration.description')}
        </Typography>

        <List disablePadding>
          {config.map((item, index) => (
            <Box key={item.label}>
              <ListItem disablePadding sx={{ py: 1.5 }}>
                <ListItemIcon sx={{ minWidth: 40 }}>
                  <item.icon color="action" />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography variant="subtitle2" color="text.secondary">
                      {item.label}
                    </Typography>
                  }
                  secondary={
                    <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}>
                      <Typography variant="body2">{item.value}</Typography>
                      {item.path && (
                        <IconButton
                          component={RouterLink}
                          to={item.path}
                          size="small"
                          sx={{ ml: 1 }}
                        >
                          <OpenInNewIcon fontSize="small" />
                        </IconButton>
                      )}
                    </Box>
                  }
                  slotProps={{
                    secondary: { component: 'div' }
                  }}
                />
              </ListItem>
              {index < config.length - 1 && <Divider />}
            </Box>
          ))}
        </List>
      </CardContent>
    </Card>
  );
}

/**
 * Runtime Overview - Mini Dashboard
 * Ties deployment to reality
 */
function RuntimeOverview({ flow }) {
  const { t } = useTranslation('console');
  const formatMetric = (value) => (
    typeof value === 'number' && Number.isFinite(value)
      ? value.toLocaleString()
      : t('flows.flowDetail.runtime.notAvailable')
  );
  const stats = [
    { label: t('flows.flowDetail.runtime.applicationsSubmittedLabel'), value: formatMetric(flow?.stats?.applications_submitted), color: 'primary' },
    { label: t('flows.flowDetail.runtime.pendingApprovalLabel'), value: formatMetric(flow?.stats?.pending_approval), color: 'warning' },
    { label: t('flows.flowDetail.runtime.credentialsIssuedLabel'), value: formatMetric(flow?.stats?.credentials_issued), color: 'success' },
    { label: t('flows.flowDetail.runtime.failures24hLabel'), value: formatMetric(flow?.stats?.failures_24h), color: 'error' },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          {t('flows.flowDetail.runtime.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
          {t('flows.flowDetail.runtime.description')}
        </Typography>

        <Grid container spacing={3}>
          {stats.map((stat) => (
            <Grid key={stat.label} size={{ xs: 12, sm: 6, md: 3 }}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color={`${stat.color}.main`} sx={{ fontWeight: 700 }}>
                  {stat.value}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {stat.label}
                </Typography>
              </Box>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
          <Button
            component={RouterLink}
            to="/console/org/operate/applications"
            variant="outlined"
            size="small"
            fullWidth
          >
            {t('flows.flowDetail.runtime.viewApplicationsButton')}
          </Button>
          <Button
            component={RouterLink}
            to="/console/org/operate/issuance"
            variant="outlined"
            size="small"
            fullWidth
          >
            {t('flows.flowDetail.runtime.viewIssuedCredentialsButton')}
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
}

function LifecycleActions({ flow, onActivated, canManage }) {
  const { t } = useTranslation('console');
  const beginAction = useAsyncActionScope();
  const busyRef = useRef(false);
  const [busy, setBusy] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const run = async (label, operation, onSuccess) => {
    if (!canManage || busyRef.current) return;
    const action = beginAction();
    busyRef.current = true;
    setBusy(label);
    setError('');
    setResult(null);
    try {
      const value = await action.run(operation);
      if (action.isCurrent()) {
        setResult({ action: label, value });
        onSuccess?.(value);
      }
    } catch (cause) {
      if (action.isCurrent()) setError(cause?.message || `${label} failed.`);
    } finally {
      if (action.isCurrent()) {
        busyRef.current = false;
        setBusy('');
      }
    }
  };

  const activate = () => run('Activation', async () => {
    const activated = await publishFlow(flow.id);
    if (activated?.id !== flow.id || activated.organization_id !== flow.organization_id || activated.status !== 'ACTIVE') {
      throw new Error(t('flows.flowDetail.errors.invalidActivation'));
    }
    return activated;
  }, onActivated);

  if (flow.status === 'ACTIVE') {
    return <Alert severity="success" icon={<CheckCircleIcon />}>This flow is active and can start new instances.</Alert>;
  }

  return (
    <Paper variant="outlined" sx={{ p: 2.5, mb: 3 }}>
      <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>{t('flows.flowDetail.lifecycleTitle')}</Typography>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
        <Button startIcon={<RuleIcon />} variant="outlined" disabled={!canManage || Boolean(busy)} onClick={() => run('Validation', () => validateFlow(flow.id))}>Validate</Button>
        <Button startIcon={<ScienceIcon />} variant="outlined" disabled={!canManage || Boolean(busy)} onClick={() => run('Dry run', () => testFlow(flow.id))}>Test</Button>
        <Button startIcon={<PlayArrowIcon />} variant="contained" disabled={!canManage || Boolean(busy)} onClick={activate}>Activate</Button>
      </Stack>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      {result && (
        <Alert severity={result.value.valid ? 'success' : 'warning'} sx={{ mt: 2 }}>
          {result.action}: {result.value.valid ? 'passed' : `${result.value.errors?.length || 0} blocker(s)`}
          {result.value.errors?.map((item) => <Box key={`${item.code}-${item.field}`}>{item.message}</Box>)}
        </Alert>
      )}
    </Paper>
  );
}

/**
 * Main Flow Detail Page Component
 */
function applicationLink(flow) {
  if (flow?.status !== 'ACTIVE' || typeof flow.public_url !== 'string' || !flow.public_url.trim()) return null;
  try {
    const url = new URL(flow.public_url);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? flow.public_url.trim() : null;
  } catch {
    return null;
  }
}

function FlowDetailSession({ flowId }) {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const { data: flow, loading, error } = useAsyncData(
    () => getFlow(flowId),
    [flowId]
  );
  const [copySuccess, setCopySuccess] = useState(false);
  const [copying, setCopying] = useState(false);
  const [copyError, setCopyError] = useState('');
  const copyBusy = useRef(false);
  const copyTimer = useRef(null);
  const beginCopy = useAsyncActionScope();
  const [activatedFlow, setActivatedFlow] = useState(null);
  const displayedFlow = activatedFlow || flow;
  const previewPath = typeof displayedFlow?.id === 'string' && displayedFlow.id.trim()
    && displayedFlow.id === flowId
    && typeof displayedFlow.organization_id === 'string' && displayedFlow.organization_id.trim()
    ? `/applicant/preview/flows/${encodeURIComponent(displayedFlow.id)}?organization_id=${encodeURIComponent(displayedFlow.organization_id)}`
    : null;
  const publicUrl = previewPath ? applicationLink(displayedFlow) : null;

  useLayoutEffect(() => () => window.clearTimeout(copyTimer.current), []);

  const handleCopyUrl = async () => {
    if (!publicUrl || copyBusy.current) return;
    const action = beginCopy();
    copyBusy.current = true;
    window.clearTimeout(copyTimer.current);
    setCopying(true);
    setCopySuccess(false);
    setCopyError('');
    try {
      await action.run(() => navigator.clipboard.writeText(publicUrl));
      if (action.isCurrent()) {
        setCopySuccess(true);
        copyTimer.current = window.setTimeout(() => {
          if (action.isCurrent()) setCopySuccess(false);
        }, 2000);
      }
    } catch {
      if (action.isCurrent()) setCopyError(t('flows.flowDetail.errors.copyFailed'));
    } finally {
      if (action.isCurrent()) {
        copyBusy.current = false;
        setCopying(false);
      }
    }
  };

  const handlePreview = () => {
    if (previewPath) {
      window.open(publicEntryHref(previewPath), '_blank', 'noopener,noreferrer');
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !flow) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">{error?.message || t('flows.flowDetail.errors.flowNotFound')}</Alert>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/flows/definitions')}
          sx={{ mt: 2 }}
        >
          {t('flows.flowDetail.actions.backToFlowsButton')}
        </Button>
      </Box>
    );
  }

  const isPublished = displayedFlow.status === 'ACTIVE';
  const statusKey = ['DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED'].includes(displayedFlow.status)
    ? displayedFlow.status.toLowerCase() : 'unknown';

  return (
    <ResourcePage
      title=""
      breadcrumbs={getBreadcrumbs(t)}
      hideTitle
    >
      {/* Hero Header */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ flex: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <IconButton
                size="small"
                onClick={() => navigate('/console/org/flows/definitions')}
              >
                <ArrowBackIcon />
              </IconButton>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>
                {displayedFlow.name}
              </Typography>
            </Box>
            <Stack direction="row" spacing={1} sx={{ ml: 5 }}>
              <Chip
                label={t(`flows.flowDetail.statusChips.${statusKey}`)}
                color={isPublished ? 'success' : displayedFlow.status === 'PAUSED' ? 'warning' : 'default'}
                size="small"
                icon={isPublished ? <CheckCircleIcon /> : <PendingIcon />}
              />
              <Chip
                label={displayedFlow.flow_type}
                size="small"
                variant="outlined"
              />
            </Stack>
          </Box>

          {/* Primary Actions */}
          <Stack direction="row" spacing={1}>
            {isPublished && (
              <>
                <Button
                  variant="contained"
                  startIcon={copySuccess ? <CheckCircleIcon /> : <ContentCopyIcon />}
                  onClick={handleCopyUrl}
                  disabled={!publicUrl || copying}
                  color={copySuccess ? 'success' : 'primary'}
                >
                  {copySuccess ? t('flows.flowDetail.actions.copied') : t('flows.flowDetail.actions.copyApplicationLink')}
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<QrCode2Icon />}
                  disabled
                  title={t('flows.flowDetail.entryPoints.qrDownloadUnavailable')}
                >
                  {t('flows.flowDetail.actions.downloadQr')}
                </Button>
              </>
            )}
          </Stack>
        </Box>

        {displayedFlow.status === 'DRAFT' && (
          <Alert severity="info" sx={{ mt: 2 }}>
            {t('flows.flowDetail.alerts.draftStatus')}
          </Alert>
        )}
        {copyError && <Alert severity="error" sx={{ mt: 2 }}>{copyError}</Alert>}
      </Paper>

      {/* Applicant Journey Timeline - THE CRITICAL SECTION */}
      <Box sx={{ mb: 3 }}>
        <ApplicantJourney flow={displayedFlow} />
      </Box>

      <LifecycleActions flow={displayedFlow} onActivated={setActivatedFlow} canManage={Boolean(previewPath)} />

      {/* Preview Button */}
      <Box sx={{ mb: 3 }}>
        <Button
          variant="outlined"
          size="large"
          fullWidth
          startIcon={<PreviewIcon />}
          onClick={handlePreview}
          disabled={!previewPath}
          sx={{ py: 1.5 }}
        >
          {t('flows.flowDetail.actions.previewButton')}
        </Button>
      </Box>

      {/* Main Content Grid */}
      <Grid container spacing={3}>
        {/* Left Column */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Stack spacing={3}>
            <EntryPoints
              publicUrl={publicUrl}
              onCopy={handleCopyUrl}
              copying={copying}
            />
          </Stack>
        </Grid>

        {/* Right Column */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Stack spacing={3}>
            <ConfigurationSummary flow={displayedFlow} />
            <RuntimeOverview flow={displayedFlow} />
          </Stack>
        </Grid>
      </Grid>

      {/* Audit Footer */}
      <Paper sx={{ p: 2, mt: 3, bgcolor: 'grey.50' }}>
        <Typography variant="caption" color="text.secondary">
          <strong>{t('flows.flowDetail.audit.createdLabel')}:</strong> {new Date(displayedFlow.created_at).toLocaleString()} •{' '}
          <strong>{t('flows.flowDetail.audit.publishedByLabel')}:</strong> {displayedFlow.published_by} •{' '}
          <strong>{t('flows.flowDetail.audit.lastModifiedLabel')}:</strong> {new Date(displayedFlow.updated_at).toLocaleString()}
        </Typography>
      </Paper>
    </ResourcePage>
  );
}

function FlowDetailPage() {
  const { flowId } = useParams();
  const location = useLocation();
  // ConsoleSessionProvider separately remounts the console on account changes.
  const entryKey = JSON.stringify([flowId, location.key, location.pathname, location.search]);
  return <FlowDetailSession key={entryKey} flowId={flowId} />;
}

export default FlowDetailPage;
