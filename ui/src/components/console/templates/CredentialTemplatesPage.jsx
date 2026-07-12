/**
 * Credential Templates Page
 * 
 * Manages credential templates - schema definitions for issuable credentials.
 */

import { useTranslation } from 'react-i18next';
import { useAsyncData } from '../../../hooks/useAsyncData';
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
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import AddIcon from '@mui/icons-material/Add';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { Link } from 'react-router-dom';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { listCredentialTemplates, listTrustProfiles } from '../../../services/presentationPolicyApi';

const getTemplatesTabs = (t) => [
  { label: t('templates.credentialTemplates'), path: '/console/org/templates/credentials' },
  { label: t('templates.applicationTemplates'), path: '/console/org/templates/applications' },
];

const getBreadcrumbs = (t) => [
  { label: t('templates.breadcrumbs.console'), path: '/console' },
  { label: t('templates.breadcrumbs.templates'), path: '/console/org/templates' },
  { label: t('templates.breadcrumbs.credentialTemplates'), path: '/console/org/templates/credentials' },
];

/**
 * Artifacts status indicator
 */
function ArtifactsStatus({ hasArtifacts, validated }) {
  const { t } = useTranslation('console');
  
  if (!hasArtifacts) {
    return (
      <Tooltip title={t('templates.artifactsStatus.missingArtifactsTooltip')}>
        <Chip 
          icon={<WarningIcon />} 
          label={t('templates.artifactsStatus.missingArtifacts')} 
          color="warning" 
          size="small" 
        />
      </Tooltip>
    );
  }
  
  if (!validated) {
    return (
      <Tooltip title={t('templates.artifactsStatus.notValidatedTooltip')}>
        <Chip label={t('templates.artifactsStatus.notValidated')} size="small" variant="outlined" />
      </Tooltip>
    );
  }
  
  return (
    <Tooltip title={t('templates.artifactsStatus.validTooltip')}>
      <Chip 
        icon={<CheckCircleIcon />} 
        label={t('templates.artifactsStatus.valid')} 
        color="success" 
        size="small" 
      />
    </Tooltip>
  );
}

function CredentialTemplatesPage() {
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;
  const { data: templatesData, loading, error } = useAsyncData(
    () => {
      if (!organizationId) {
        throw new Error('Select an organization before loading credential templates.');
      }
      return listCredentialTemplates({ organization_id: organizationId });
    },
    [organizationId]
  );

  const {
    data: trustProfiles = [],
    loading: trustProfilesLoading,
    error: trustProfilesError,
  } = useAsyncData(
    () => {
      if (!organizationId) {
        throw new Error('Select an organization before loading trust profile prerequisites.');
      }
      return listTrustProfiles({ organization_id: organizationId, limit: 1 });
    },
    [organizationId]
  );
  const safeTrustProfiles = Array.isArray(trustProfiles) ? trustProfiles : [];

  const templatePrerequisites = [
    {
      label: t('templates.prerequisites.trustProfile', { defaultValue: 'Trust Profile' }),
      status: trustProfilesError ? 'error' : trustProfilesLoading ? 'pending' : safeTrustProfiles.length > 0 ? 'ready' : 'missing',
      path: '/console/org/trust/profiles',
    },
  ];
  const templates = Array.isArray(templatesData)
    ? templatesData
    : Array.isArray(templatesData?.items)
      ? templatesData.items
      : Array.isArray(templatesData?.templates)
        ? templatesData.templates
        : [];

  const normalizeFormatLabel = (rawFormat) => {
    if (!rawFormat) {
      return null;
    }

    const normalized = String(rawFormat).trim().toLowerCase();
    if (!normalized) {
      return null;
    }

    const aliasMap = {
      sd_jwt_vc: 'SD_JWT_VC',
      ietf_sd_jwt_vc: 'SD_JWT_VC',
      w3c_vcdm_v2_sd_jwt: 'SD_JWT_VC',
      mdoc: 'MDOC',
      iso_mdoc: 'MDOC',
      vc_jwt: 'VC_JWT',
      jwt_vc: 'VC_JWT',
      json_ld: 'JSON_LD',
      ldp_vc: 'JSON_LD',
    };

    return aliasMap[normalized] || String(rawFormat).toUpperCase();
  };

  const getTemplateFormatLabel = (template) => {
    const direct = normalizeFormatLabel(template?.format)
      || normalizeFormatLabel(template?.credential_format)
      || normalizeFormatLabel(template?.credential_payload_format);

    if (direct) {
      return direct;
    }

    if (Array.isArray(template?.supported_formats) && template.supported_formats.length > 0) {
      return normalizeFormatLabel(template.supported_formats[0]) || 'UNKNOWN';
    }

    return 'UNKNOWN';
  };

  const getClaimsCount = (template) => {
    if (Array.isArray(template?.claims)) {
      return template.claims.length;
    }
    if (typeof template?.claims === 'number') {
      return template.claims;
    }
    if (Array.isArray(template?.schema?.claims)) {
      return template.schema.claims.length;
    }
    return 0;
  };

  const getUpdatedDateLabel = (template) => {
    const raw = template?.updatedAt || template?.updated_at || template?.createdAt || template?.created_at;
    if (!raw) {
      return '—';
    }
    const parsed = new Date(raw);
    return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleDateString();
  };

  // Count templates with missing artifacts
  const missingArtifactsCount = templates.filter((template) => !template?.hasArtifacts).length;

  return (
    <ResourcePage
      title={t('templates.credentialTemplates')}
      description={t('templates.credentialTemplatesDescription')}
      resourceName={t('templates.title')}
      buildPath="/console/org/templates/credentials/new"
      newPath="/console/org/templates/credentials/new?mode=advanced"
      tabs={getTemplatesTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {trustProfilesError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {trustProfilesError?.message || t('templates.prerequisites.loadFailed', { defaultValue: 'Unable to load trust profile prerequisites.' })}
        </Alert>
      )}

      {/* Guardrail Banner */}
      <Alert 
        severity="info" 
        icon={<InfoOutlinedIcon />}
        sx={{ mb: 3 }}
      >
        <Typography variant="body2" fontWeight={600} gutterBottom>
          {t('templates.guardrailTitle')}
        </Typography>
        <Typography variant="body2">
          {t('templates.guardrailDescription')}
        </Typography>
      </Alert>

      {missingArtifactsCount > 0 && (
        <Alert 
          severity="warning" 
          sx={{ mb: 3 }}
          action={
            <Button color="inherit" size="small">
              {t('templates.validateAll')}
            </Button>
          }
        >
          {t('templates.missingArtifactsWarning', { count: missingArtifactsCount })}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : templates.length === 0 ? (
        <EmptyState
          {...EmptyStates.templates}
          prerequisites={templatePrerequisites}
          whyItMatters={t(
            'templates.prerequisites.whyItMatters',
            { defaultValue: 'Credential templates define the claims schema and format for issuable credentials. A trust profile must be configured first so signatures can be verified when the credential is presented.' }
          )}
        />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('templates.tableHeaders.name')}</TableCell>
                <TableCell>{t('templates.tableHeaders.format')}</TableCell>
                <TableCell>{t('templates.tableHeaders.version')}</TableCell>
                <TableCell align="right">{t('templates.tableHeaders.claims')}</TableCell>
                <TableCell>{t('templates.tableHeaders.artifacts')}</TableCell>
                <TableCell>{t('templates.tableHeaders.usedBy')}</TableCell>
                <TableCell>{t('templates.tableHeaders.status')}</TableCell>
                <TableCell>{t('templates.tableHeaders.lastUpdated')}</TableCell>
                <TableCell align="right">{t('templates.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {templates.map((template) => (
                  <TableRow key={template.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {template.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={getTemplateFormatLabel(template)} 
                        size="small" 
                        variant="outlined" 
                      />
                    </TableCell>
                    <TableCell>{template.version}</TableCell>
                    <TableCell align="right">{getClaimsCount(template)}</TableCell>
                    <TableCell>
                      <ArtifactsStatus 
                        hasArtifacts={template.hasArtifacts} 
                        validated={template.artifactsValidated} 
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={t('templates.usedByFlowsTooltip')}>
                        <Chip 
                          label={t('templates.usedByFlows', { count: template.usedByFlowsCount })}
                          size="small"
                          color={template.usedByFlowsCount > 0 ? 'primary' : 'default'}
                          variant={template.usedByFlowsCount > 0 ? 'filled' : 'outlined'}
                        />
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <StatusChip status={template.status} />
                    </TableCell>
                    <TableCell>
                      {getUpdatedDateLabel(template)}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('templates.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/templates/credentials/${template.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('templates.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/templates/credentials/${template.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('templates.actions.createIssuanceFlow')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/flows/definitions/new?templateId=${template.id}`}
                          size="small"
                          color="primary"
                        >
                          <AddIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default CredentialTemplatesPage;
