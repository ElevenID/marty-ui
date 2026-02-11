/**
 * Flow Detail Page
 * 
 * THE CENTERPIECE: This page represents the applicant-facing product.
 * If an admin understands this page, they understand ElevenID.
 * 
 * Enforces the mental model: Applicants apply to Flows, not Templates.
 */

import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import { useNotification } from '../../../contexts/NotificationContext';
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

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Deploy', path: '/console/deploy' },
  { label: 'Issuance Flows', path: '/console/flows/definitions' },
  { label: 'Flow Detail', path: '' },
];

/**
 * Applicant Journey Timeline - THE MOST IMPORTANT SECTION
 * Makes the end-to-end path undeniable
 */
function ApplicantJourney() {
  const steps = [
    'Visit Application Link',
    'Complete Application',
    'Submit',
    'Await Approval',
    'Scan QR',
    'Credential Issued',
  ];

  return (
    <Card elevation={0} sx={{ bgcolor: 'primary.50', border: 1, borderColor: 'primary.100' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
          Applicant Journey
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          What the applicant experiences from start to finish
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
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
          Applicant Entry Points
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
          Share these with applicants to start the credential issuance process
        </Typography>

        {/* Application URL */}
        <Typography variant="subtitle2" gutterBottom>
          Application URL
        </Typography>
        <TextField
          fullWidth
          value={publicUrl || 'Not published - flow must be published first'}
          disabled={!publicUrl}
          size="small"
          InputProps={{
            readOnly: true,
            endAdornment: publicUrl && (
              <InputAdornment position="end">
                <Tooltip title="Copy URL">
                  <IconButton onClick={onCopy} edge="end" size="small">
                    <ContentCopyIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Open in new tab">
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
          QR Code
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
              Download QR Code
            </Button>
          </Box>
        ) : (
          <Alert severity="info" sx={{ mt: 1 }}>
            QR code will be generated when flow is published
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
  const config = [
    {
      label: 'Credential Template',
      value: flow?.credential_template_name || 'EU Digital Identity Credential',
      path: `/console/templates/credentials/${flow?.credential_template_id}`,
      icon: DescriptionIcon,
    },
    {
      label: 'Application Rules',
      value: flow?.application_rules || 'Employee email required (domain: example.com)',
      path: `/console/templates/applications/${flow?.application_template_id}`,
      icon: PolicyIcon,
    },
    {
      label: 'Compliance Profile',
      value: flow?.compliance_profile || 'Open Badge 2.0, EUDI-ready',
      path: `/console/policies/compliance/${flow?.compliance_profile_id}`,
      icon: VerifiedUserIcon,
    },
    {
      label: 'Approval Mode',
      value: flow?.approval_mode === 'auto' ? 'Automatic Approval' : 'Manual Approval Required',
      icon: CheckCircleIcon,
    },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
          Flow Configuration
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 2 }}>
          Read-only view of how this flow is configured
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
  const stats = [
    { label: 'Applications Submitted', value: flow?.stats?.applications_submitted || 142, color: 'primary' },
    { label: 'Pending Approval', value: flow?.stats?.pending_approval || 12, color: 'warning' },
    { label: 'Credentials Issued', value: flow?.stats?.credentials_issued || 130, color: 'success' },
    { label: 'Failures (24h)', value: flow?.stats?.failures_24h || 0, color: 'error' },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom fontWeight={600}>
          Runtime Overview
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
          Real-time operational metrics for this flow
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
            to="/console/operate/applications"
            variant="outlined"
            size="small"
            fullWidth
          >
            View Applications
          </Button>
          <Button
            component={RouterLink}
            to="/console/operate/issuance"
            variant="outlined"
            size="small"
            fullWidth
          >
            View Issued Credentials
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
  const [flow, setFlow] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copySuccess, setCopySuccess] = useState(false);

  useEffect(() => {
    const loadFlow = async () => {
      try {
        // TODO: Replace with actual API call
        // const data = await flowsApi.getFlow(flowId);
        
        // Mock data for now
        await new Promise(resolve => setTimeout(resolve, 500));
        setFlow({
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
        });
      } catch (err) {
        setError('Failed to load flow details');
        console.error('Failed to load flow details:', err);
        showError('Unable to load flow details', {
          details: 'The backend service may be unavailable. Check console for details.',
        });
      } finally {
        setLoading(false);
      }
    };

    loadFlow();
  }, [flowId]);

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
        <Alert severity="error">{error || 'Flow not found'}</Alert>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/flows/definitions')}
          sx={{ mt: 2 }}
        >
          Back to Issuance Flows
        </Button>
      </Box>
    );
  }

  const isPublished = flow.status === 'PUBLISHED';

  return (
    <ResourcePage
      title=""
      breadcrumbs={BREADCRUMBS}
      hideTitle
    >
      {/* Hero Header */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ flex: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <IconButton
                size="small"
                onClick={() => navigate('/console/flows/definitions')}
              >
                <ArrowBackIcon />
              </IconButton>
              <Typography variant="h4" fontWeight={700}>
                {flow.name}
              </Typography>
            </Box>
            <Stack direction="row" spacing={1} sx={{ ml: 5 }}>
              <Chip
                label={isPublished ? 'Published' : 'Draft'}
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
                  {copySuccess ? 'Copied!' : 'Copy Application Link'}
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<QrCode2Icon />}
                  onClick={handleDownloadQR}
                >
                  Download QR
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
            This flow is in draft status. Publish the flow to make it available to applicants.
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
            Preview Applicant Experience
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
                    Operational Controls
                  </Typography>
                  <Stack spacing={1}>
                    <Button
                      variant="outlined"
                      startIcon={<PauseCircleIcon />}
                      fullWidth
                    >
                      Pause Flow
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<RefreshIcon />}
                      fullWidth
                    >
                      Rotate QR Code
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
          <strong>Created:</strong> {new Date(flow.created_at).toLocaleString()} •{' '}
          <strong>Published by:</strong> {flow.published_by} •{' '}
          <strong>Last modified:</strong> {new Date(flow.updated_at).toLocaleString()}
        </Typography>
      </Paper>
    </ResourcePage>
  );
}

export default FlowDetailPage;
