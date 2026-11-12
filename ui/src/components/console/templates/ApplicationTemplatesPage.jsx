import { loadScopedCatalog } from '../../../services/loadScopedCatalog';
/**
 * Application Templates Page
 * 
 * Manages application templates - forms and workflows for credential applications.
 */

import { useAsyncData } from '../../../hooks/useAsyncData';
import { useDialog } from '../../../hooks/useDialog';
import { useAuth } from '../../../hooks/useAuth';
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
  Button,
  LinearProgress,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import PreviewIcon from '@mui/icons-material/Preview';
import RuleIcon from '@mui/icons-material/Rule';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useConsole } from '../../../contexts/ConsoleContext';
import { listApplicationTemplates } from '../../../services/applicationTemplatesApi';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import CheckConfigurationDialog from './CheckConfigurationDialog';

function ApplicationTemplatesContent({ organizationId }) {
  const { t } = useTranslation('console');
  const { data: templatesData, loading, error, reload } = useAsyncData(async () => {
    const data = await listApplicationTemplates(organizationId);
    if (!Array.isArray(data) || data.some((template) => typeof template?.id !== 'string'
      || !template.id.trim() || template.organization_id !== organizationId
      || (template.required_checks != null && !Array.isArray(template.required_checks))
      || (template.form_fields != null && !Array.isArray(template.form_fields)))) {
      throw new Error(t('applicationTemplatesPage.errors.invalidInventory', {
        defaultValue: 'Application templates could not be loaded for the selected organization.',
      }));
    }
    return data;
  }, [organizationId]);
  const templates = templatesData ?? [];

  const {
    data: credentialTemplates,
    loading: credentialTemplatesLoading,
    error: credentialTemplatesError,
    reload: reloadCredentialTemplates,
  } = useAsyncData(() => loadScopedCatalog(listCredentialTemplates, organizationId), [organizationId]);

  const credentialTemplateNameById = Object.fromEntries(
    (Array.isArray(credentialTemplates) ? credentialTemplates : []).map((ct) => [ct.id, ct.name])
  );
  const credentialTemplateClaimsCountById = Object.fromEntries(
    (Array.isArray(credentialTemplates) ? credentialTemplates : []).map((ct) => {
      const claimsCount = Array.isArray(ct?.claims)
        ? ct.claims.length
        : (typeof ct?.claims === 'number' ? ct.claims : 0);
      return [ct.id, claimsCount];
    })
  );
  const checksDialog = useDialog();

  const getTemplatesTabs = () => [
    { label: t('templates.credentialTemplates'), path: '/console/org/templates/credentials' },
    { label: t('templates.applicationTemplates'), path: '/console/org/templates/applications' },
  ];

  const getBreadcrumbs = () => [
    { label: t('applicationTemplatesPage.breadcrumbs.console'), path: '/console' },
    { label: t('applicationTemplatesPage.breadcrumbs.templates'), path: '/console/org/templates' },
    { label: t('applicationTemplatesPage.breadcrumbs.applicationTemplates'), path: '/console/org/templates/applications' },
  ];

  const handleChecksSaved = () => {
    reload();
  };

  const getTemplateFieldsCount = (template) => {
    if (Array.isArray(template?.form_fields) && template.form_fields.length > 0) {
      return template.form_fields.length;
    }

    if (credentialTemplatesLoading || credentialTemplatesError) return '—';
    return credentialTemplateClaimsCountById[template?.credential_template_id] ?? '—';
  };

  return (
    <>
    <ResourcePage
      title={t('applicationTemplatesPage.title')}
      description={t('applicationTemplatesPage.description')}
      resourceName={t('applicationTemplatesPage.resourceName')}
      buildPath="/console/org/templates/applications/new"
      newPath="/console/org/templates/applications/new?mode=advanced"
      tabs={getTemplatesTabs()}
      breadcrumbs={getBreadcrumbs()}
    >
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={<Button color="inherit" size="small" onClick={reload}>{t('common.retry', { defaultValue: 'Retry' })}</Button>}
        >
          {error.message?.trim() || t('applicationTemplatesPage.errors.loadFailed', {
            defaultValue: 'Application templates could not be loaded.',
          })}
        </Alert>
      )}

      {credentialTemplatesError && (
        <Alert
          severity="warning"
          sx={{ mb: 3 }}
          action={(
            <Button color="inherit" size="small" onClick={reloadCredentialTemplates}>
              {t('applicationTemplatesPage.actions.retryCredentialDetails', { defaultValue: 'Retry credential details' })}
            </Button>
          )}
        >
          {t('applicationTemplatesPage.errors.credentialDetailsUnavailable', {
            defaultValue: 'Credential template details could not be loaded. Names and derived field counts may be unavailable.',
          })}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : error ? null : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('applicationTemplatesPage.tableHeaders.name')}</TableCell>
                <TableCell>{t('applicationTemplatesPage.tableHeaders.credentialType')}</TableCell>
                <TableCell align="right">{t('applicationTemplatesPage.tableHeaders.fields')}</TableCell>
                <TableCell>Checks</TableCell>
                <TableCell>{t('applicationTemplatesPage.tableHeaders.status')}</TableCell>
                <TableCell>{t('applicationTemplatesPage.tableHeaders.lastUpdated')}</TableCell>
                <TableCell align="right">{t('applicationTemplatesPage.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {templates.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7}>
                    <EmptyState {...EmptyStates.applicationTemplates} />
                  </TableCell>
                </TableRow>
              ) : (
                templates.map((template) => (
                  <TableRow key={template.id} hover>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {template.name}
                      </Typography>
                      {template.description && (
                        <Typography variant="caption" color="text.secondary">
                          {template.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      {credentialTemplateNameById[template.credential_template_id] || template.credential_template_id || '—'}
                    </TableCell>
                    <TableCell align="right">{getTemplateFieldsCount(template)}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                        {(template.required_checks || []).length === 0 ? (
                          <Chip label="default" size="small" variant="outlined" color="default" />
                        ) : (
                          <Chip
                            label={`${template.required_checks.length} check${template.required_checks.length !== 1 ? 's' : ''}`}
                            size="small"
                            color="primary"
                            variant="outlined"
                          />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <StatusChip status={template.status} />
                    </TableCell>
                    <TableCell>
                      {template.updated_at ? new Date(template.updated_at).toLocaleDateString() : '—'}
                    </TableCell>
                    <TableCell align="right">
                      {String(template.status || '').toUpperCase() === 'DRAFT' && <Tooltip title="Configure required checks">
                          <IconButton
                            size="small"
                            color="secondary"
                            onClick={() => checksDialog.open(template)}
                          >
                            <RuleIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>}
                      <Tooltip title={t('applicationTemplatesPage.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/templates/applications/${template.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {String(template.status || '').toUpperCase() === 'DRAFT' && <Tooltip title={t('applicationTemplatesPage.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/templates/applications/${template.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>}
                      <Tooltip title={t('applicationTemplatesPage.actions.previewForm')}>
                        <IconButton
                          onClick={() => window.open(`/applicant/preview/applications/${template.id}`, '_blank')}
                          size="small"
                          color="primary"
                        >
                          <PreviewIcon fontSize="small" />
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
    </ResourcePage>
    <CheckConfigurationDialog
      open={checksDialog.isOpen}
      template={checksDialog.data}
      onClose={checksDialog.close}
      onSaved={handleChecksSaved}
    />
    </>
  );
}

function ApplicationTemplatesPage() {
  const { t } = useTranslation('console');
  const { activeOrgId: organizationId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const principalId = isAuthenticated ? user?.user_id || user?.sub || user?.id || 'unknown-user' : 'signed-out';
  if (!organizationId) {
    return <Alert severity="error">{t('applicationTemplatesPage.errors.selectOrganization', {
      defaultValue: 'Select an organization before loading application templates.',
    })}</Alert>;
  }
  return <ApplicationTemplatesContent key={`${principalId}:${organizationId}`} organizationId={organizationId} />;
}

export default ApplicationTemplatesPage;
