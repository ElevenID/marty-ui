/**
 * Flow Detail Page
 * 
 * THE CENTERPIECE: This page represents the applicant-facing product.
 * If an admin understands this page, they understand ElevenID LLC.
 * 
 * Enforces the mental model: Applicants apply to Flows, not Templates.
 */

import { useState } from 'react';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAsyncData } from '../../../hooks/useAsyncData';
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
import MoreVertIcon from '@mui/icons-material/MoreVert';
import PreviewIcon from '@mui/icons-material/Preview';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PendingIcon from '@mui/icons-material/Pending';
import SmartphoneIcon from '@mui/icons-material/Smartphone';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import PauseCircleIcon from '@mui/icons-material/PauseCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

import { ResourcePage, StatusChip } from '../../common';
import flowsApi from '../../../services/flowsApi';

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
function ApplicantJourney() {
  const { t } = useTranslation('console');
  const steps = [
    t('flows.flowDetail.applicantJourney.steps.visitLink'),
    t('flows.flowDetail.applicantJourney.steps.completeApplication'),
    t('flows.flowDetail.applicantJourney.steps.submit'),
    t('flows.flowDetail.applicantJourney.steps.awaitApproval'),
    t('flows.flowDetail.applicantJourney.steps.scanQr'),
    t('flows.flowDetail.applicantJourney.steps.credentialIssued'),
  ];

  return (
    <Card elevation={0} sx={{ bgcolor: 'primary.50', border: 1, borderColor: 'primary.100' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
          {t('flows.flowDetail.applicantJourney.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {t('flows.flowDetail.applicantJourney.description')}
        </Typography>
        
        <Box sx={{ mt: 3 }}>
          <Stepper activeStep={-1} alternativeLabel>
            {steps.map((label, index) => (
              <Step key={label}>
                <StepLabel
                  StepIconProps={{
                    sx: {
                      color: 'primary.main',
                      '&.Mui-active': { color: 'primary.main' },
                    },
                  }}
                >
                  <Typography variant="caption">{label}</Typography>
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
function EntryPoints({ flow, publicUrl, onCopy, onDownloadQR }) {
  const { t } = useTranslation('console');
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
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
          value={publicUrl || t('flows.flowDetail.entryPoints.notPublished')}
          disabled={!publicUrl}
          size="small"
          InputProps={{
            readOnly: true,
            endAdornment: publicUrl && (
              <InputAdornment position="end">
                <Tooltip title={t('flows.flowDetail.entryPoints.copyUrlTooltip')}>
                  <IconButton onClick={onCopy} edge="end" size="small">
                    <ContentCopyIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Tooltip title={t('flows.flowDetail.entryPoints.openInNewTabTooltip')}>
                  <IconButton onClick={() => window.open(publicUrl, '_blank')} edge="end" size="small">
                    <OpenInNewIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              </InputAdornment>
            ),
          }}
          sx={{ mb: 3 }}
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
              onClick={onDownloadQR}
              size="small"
            >
              {t('flows.flowDetail.entryPoints.downloadQrButton')}
            </Button>
          </Box>
        ) : (
          <Alert severity="info" sx={{ mt: 1 }}>
            {t('flows.flowDetail.entryPoints.qrCodeAlert')}
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
  const config = [
    {
      label: t('flows.flowDetail.configuration.credentialTemplateLabel'),
      value: flow?.credential_template_name || 'EU Digital Identity Credential',
      path: `/console/org/templates/credentials/${flow?.credential_template_id}`,
      icon: DescriptionIcon,
    },
    {
      label: t('flows.flowDetail.configuration.applicationRulesLabel'),
      value: flow?.application_rules || 'Employee email required (domain: example.com)',
      path: `/console/org/templates/applications/${flow?.application_template_id}`,
      icon: PolicyIcon,
    },
    {
      label: t('flows.flowDetail.configuration.complianceProfileLabel'),
      value: flow?.compliance_profile || 'Open Badge 2.0, EUDI-ready',
      path: `/console/org/policies/compliance/${flow?.compliance_profile_id}`,
      icon: VerifiedUserIcon,
    },
    {
      label: t('flows.flowDetail.configuration.approvalModeLabel'),
      value: flow?.approval_mode === 'auto' ? t('flows.flowDetail.configuration.approvalModeAuto') : t('flows.flowDetail.configuration.approvalModeManual'),
      icon: CheckCircleIcon,
    },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
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
  const stats = [
    { label: t('flows.flowDetail.runtime.applicationsSubmittedLabel'), value: flow?.stats?.applications_submitted || 142, color: 'primary' },
    { label: t('flows.flowDetail.runtime.pendingApprovalLabel'), value: flow?.stats?.pending_approval || 12, color: 'warning' },
    { label: t('flows.flowDetail.runtime.credentialsIssuedLabel'), value: flow?.stats?.credentials_issued || 130, color: 'success' },
    { label: t('flows.flowDetail.runtime.failures24hLabel'), value: flow?.stats?.failures_24h || 0, color: 'error' },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
          {t('flows.flowDetail.runtime.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
          {t('flows.flowDetail.runtime.description')}
        </Typography>

        <Grid container spacing={3}>
          {stats.map((stat) => (
            <Grid item xs={12} sm={6} md={3} key={stat.label}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" fontWeight={700} color={`${stat.color}.main`}>
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

/**
 * Main Flow Detail Page Component
 */
function FlowDetailPage() {
  const { flowId } = useParams();
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const { data: flow, loading, error } = useAsyncData(async () => {
    // TODO: Replace with actual API call
    await new Promise(resolve => setTimeout(resolve, 500));
    return {
      id: flowId,
      name: 'EU Digital Identity – Employee Issuance',
      status: 'PUBLISHED',
      environment: 'Production',
      credential_template_name: 'EU Digital Identity Credential',
      credential_template_id: 'ct-1',
      application_rules: 'Employee email required (domain: example.com)',
      application_template_id: 'at-1',
      compliance_profile: 'Open Badge 2.0, EUDI-ready',
      compliance_profile_id: 'cp-1',
      approval_mode: 'manual',
      public_url: `${window.location.origin}/apply/${flowId}`,
      created_at: '2026-01-15T10:00:00Z',
      published_by: 'admin@example.com',
      updated_at: '2026-02-08T14:30:00Z',
      stats: {
        applications_submitted: 142,
        pending_approval: 12,
        credentials_issued: 130,
        failures_24h: 0,
      },
    };
  }, [flowId]);
  const [copySuccess, setCopySuccess] = useState(false);

  const handleCopyUrl = () => {
    if (flow?.public_url) {
      navigator.clipboard.writeText(flow.public_url);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    }
  };

  const handleDownloadQR = () => {
    // TODO: Implement QR code download
    console.log('Download QR code');
  };

  const handlePreview = () => {
    if (flow?.public_url) {
      window.open(flow.public_url, '_blank');
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

  const isPublished = flow.status === 'PUBLISHED';

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
              <Typography variant="h4" fontWeight={700}>
                {flow.name}
              </Typography>
            </Box>
            <Stack direction="row" spacing={1} sx={{ ml: 5 }}>
              <Chip
                label={isPublished ? t('flows.flowDetail.statusChips.published') : t('flows.flowDetail.statusChips.draft')}
                color={isPublished ? 'success' : 'default'}
                size="small"
                icon={isPublished ? <CheckCircleIcon /> : <PendingIcon />}
              />
              <Chip
                label={flow.environment}
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
                  color={copySuccess ? 'success' : 'primary'}
                >
                  {copySuccess ? t('flows.flowDetail.actions.copied') : t('flows.flowDetail.actions.copyApplicationLink')}
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<QrCode2Icon />}
                  onClick={handleDownloadQR}
                >
                  {t('flows.flowDetail.actions.downloadQr')}
                </Button>
              </>
            )}
            <IconButton>
              <MoreVertIcon />
            </IconButton>
          </Stack>
        </Box>

        {!isPublished && (
          <Alert severity="info" sx={{ mt: 2 }}>
            {t('flows.flowDetail.alerts.draftStatus')}
          </Alert>
        )}
      </Paper>

      {/* Applicant Journey Timeline - THE CRITICAL SECTION */}
      <Box sx={{ mb: 3 }}>
        <ApplicantJourney />
      </Box>

      {/* Preview Button */}
      {isPublished && (
        <Box sx={{ mb: 3 }}>
          <Button
            variant="outlined"
            size="large"
            fullWidth
            startIcon={<PreviewIcon />}
            onClick={handlePreview}
            sx={{ py: 1.5 }}
          >
            {t('flows.flowDetail.actions.previewButton')}
          </Button>
        </Box>
      )}

      {/* Main Content Grid */}
      <Grid container spacing={3}>
        {/* Left Column */}
        <Grid item xs={12} md={6}>
          <Stack spacing={3}>
            <EntryPoints
              flow={flow}
              publicUrl={isPublished ? flow.public_url : null}
              onCopy={handleCopyUrl}
              onDownloadQR={handleDownloadQR}
            />
            
            {isPublished && (
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom fontWeight={600}>
                    {t('flows.flowDetail.operationalControls.title')}
                  </Typography>
                  <Stack spacing={1}>
                    <Button
                      variant="outlined"
                      startIcon={<PauseCircleIcon />}
                      fullWidth
                    >
                      {t('flows.flowDetail.operationalControls.pauseFlowButton')}
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<RefreshIcon />}
                      fullWidth
                    >
                      {t('flows.flowDetail.operationalControls.rotateQrButton')}
                    </Button>
                  </Stack>
                </CardContent>
              </Card>
            )}
          </Stack>
        </Grid>

        {/* Right Column */}
        <Grid item xs={12} md={6}>
          <Stack spacing={3}>
            <ConfigurationSummary flow={flow} />
            <RuntimeOverview flow={flow} />
          </Stack>
        </Grid>
      </Grid>

      {/* Audit Footer */}
      <Paper sx={{ p: 2, mt: 3, bgcolor: 'grey.50' }}>
        <Typography variant="caption" color="text.secondary">
          <strong>{t('flows.flowDetail.audit.createdLabel')}:</strong> {new Date(flow.created_at).toLocaleString()} •{' '}
          <strong>{t('flows.flowDetail.audit.publishedByLabel')}:</strong> {flow.published_by} •{' '}
          <strong>{t('flows.flowDetail.audit.lastModifiedLabel')}:</strong> {new Date(flow.updated_at).toLocaleString()}
        </Typography>
      </Paper>
    </ResourcePage>
  );
}

export default FlowDetailPage;
