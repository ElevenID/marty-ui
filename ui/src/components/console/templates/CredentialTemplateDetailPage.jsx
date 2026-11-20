import {
  Alert,
  Box,
  Chip,
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
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import WarningIcon from '@mui/icons-material/Warning';
import { useParams } from 'react-router';
import { useState } from 'react';

import { ResourcePage } from '../../common';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import { getCredentialTemplate } from '../../../services/presentationPolicyApi';
import TemplateWalletCompatibility from './TemplateWalletCompatibility';
import { listDeliveryDestinations } from '../../../services/deliveryDestinationsApi';

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
  if (destination.mode === 'holder_wallet') return 'Wallet';
  return destination.provider || destination.mode || 'Destination';
}

function destinationIcon(destination = {}) {
  if (destination.mode === 'holder_wallet') return <WalletIcon color="action" />;
  return <OpenInNewIcon color="action" />;
}

function DestinationCard({ destination }) {
  const destinationEnabled = destination.is_enabled !== false;
  return (
    <Paper variant="outlined" sx={{ p: 2, borderRadius: 1 }}>
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1.5} sx={{ alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <Stack direction="row" spacing={1.25} sx={{ alignItems: 'center' }}>
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
            label={destinationEnabled ? 'Enabled' : 'Disabled'}
            color={destinationEnabled ? 'success' : 'default'}
            icon={destinationEnabled ? <CheckCircleIcon /> : <WarningIcon />}
          />
        </Stack>

        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Chip size="small" label={providerLabel(destination)} variant="outlined" />
          <Chip size="small" label={destination.setup_actor || 'system'} variant="outlined" />
          <Chip size="small" label={destination.credential_format || 'Any format'} variant="outlined" />
        </Box>

      </Stack>
    </Paper>
  );
}

function CredentialTemplateDetail({ templateId, organizationId, canViewDestinations }) {
  const [activeTab, setActiveTab] = useState('overview');

  const {
    data: template,
    loading: templateLoading,
    error: templateError,
  } = useAsyncData(async () => {
    const result = await getCredentialTemplate(templateId);
    if (result?.id !== templateId || result?.organization_id !== organizationId) {
      throw new Error('Credential template is outside the selected organization.');
    }
    return result;
  }, [templateId, organizationId]);
  const destinationsVisible = Boolean(template && activeTab === 'destinations' && canViewDestinations);

  const {
    data: destinationsData = [],
    error: destinationsError,
  } = useAsyncData(
    () => {
      if (!destinationsVisible) return Promise.resolve([]);
      return listDeliveryDestinations({ organizationId, activeOnly: false }).then((result) => {
        if (!Array.isArray(result) || !result.every((destination) => typeof destination?.id === 'string'
          && (destination.is_system === true ? destination.organization_id == null : destination.organization_id === organizationId))) {
          throw new Error('Destination inventory is invalid or outside the selected organization.');
        }
        return result;
      });
    },
    [organizationId, destinationsVisible],
  );

  const destinations = Array.isArray(destinationsData) ? destinationsData : [];

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
          <Tab value="wallet" label="Wallet profile" />
        </Tabs>
      </Box>

      {!template ? null : activeTab === 'wallet' ? <TemplateWalletCompatibility template={template} organizationId={organizationId} /> : activeTab === 'overview' ? (
        <Paper variant="outlined" sx={{ p: 3, borderRadius: 1 }}>
          <Stack spacing={2}>
            <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
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
      ) : !canViewDestinations ? <Alert severity="error">You do not have permission to view delivery destinations.</Alert> : (
        <Stack spacing={2}>
          <Alert severity="info">
            Destinations describe where an issued credential can be claimed or delivered.
            Configuration does not establish successful delivery or wallet interoperability.
          </Alert>
          {destinationsError ? (
            <Alert severity="error">
              {destinationsError?.message || 'Delivery destinations could not be loaded.'}
            </Alert>
          ) : null}
          <Stack spacing={2} data-testid="credential-template-destinations">
            {destinations.map((destination) => (
              <DestinationCard
                key={destination.id}
                destination={destination}
              />
            ))}
            {!destinations.length && !destinationsError ? (
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

function CredentialTemplateDetailPage() {
  const { templateId } = useParams();
  const { activeOrgId } = useConsole();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before loading a credential template.</Alert>;
  if (isLoading) return <LinearProgress />;
  if (!can('credential-template', 'view')) return <Alert severity="error">You do not have permission to view credential templates.</Alert>;
  const grants = {
    canViewDestinations: can('wallet', 'view'),
  };
  return <CredentialTemplateDetail key={`${activeOrgId}:${templateId}:${Object.values(grants).join(':')}`} organizationId={activeOrgId} templateId={templateId} {...grants} />;
}

export default CredentialTemplateDetailPage;
