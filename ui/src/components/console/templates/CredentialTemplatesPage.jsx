/**
 * Credential Templates Page
 * 
 * Manages credential templates - schema definitions for issuable credentials.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNotification } from '../../../contexts/NotificationContext';
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
  const { showError, showWarning } = useNotification();
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // TODO: Fetch credential templates from API
    const loadTemplates = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setTemplates([
          {
            id: 'ct-1',
            name: 'EU Digital Identity Credential',
            format: 'sd-jwt-vc',
            version: '1.0.0',
            claims: 12,
            hasArtifacts: true,
            artifactsValidated: true,
            status: 'active',
            updatedAt: '2026-02-06T10:30:00Z',
            usedByFlowsCount: 3,
          },
          {
            id: 'ct-2',
            name: 'Mobile Driving License',
            format: 'mdoc',
            version: '1.0.0',
            claims: 18,
            hasArtifacts: true,
            artifactsValidated: true,
            status: 'active',
            updatedAt: '2026-02-05T14:20:00Z',
            usedByFlowsCount: 2,
          },
          {
            id: 'ct-3',
            name: 'Employee Badge',
            format: 'jwt-vc',
            version: '0.9.0',
            claims: 8,
            hasArtifacts: false,
            artifactsValidated: false,
            status: 'draft',
            updatedAt: '2026-02-07T09:00:00Z',
            usedByFlowsCount: 0,
          },
        ]);
      } catch (err) {
        console.error('Failed to load credential templates:', err);
        setError(t('templates.failedToLoad'));
        showError(t('templates.failedToLoad'), {
          details: 'The backend service may be unavailable. Check console for details.',
        });
      } finally {
        setLoading(false);
      }
    };
    loadTemplates();
  }, []);

  // Count templates with missing artifacts
  const missingArtifactsCount = templates.filter((t) => !t.hasArtifacts).length;

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
          {error}
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
        <EmptyState {...EmptyStates.templates} />
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
                        label={template.format.toUpperCase()} 
                        size="small" 
                        variant="outlined" 
                      />
                    </TableCell>
                    <TableCell>{template.version}</TableCell>
                    <TableCell align="right">{template.claims}</TableCell>
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
                      {new Date(template.updatedAt).toLocaleDateString()}
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
