/**
 * Application Templates Page
 * 
 * Manages application templates - forms and workflows for credential applications.
 */

import { useAsyncData } from '../../../hooks/useAsyncData';
import { useDialog } from '../../../hooks/useDialog';
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
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import PreviewIcon from '@mui/icons-material/Preview';
import RuleIcon from '@mui/icons-material/Rule';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../../../hooks/useAuth';
import { listApplicationTemplates } from '../../../services/applicationTemplatesApi';
import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import CheckConfigurationDialog from './CheckConfigurationDialog';

function ApplicationTemplatesPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { data: templates = [], loading, error, reload } = useAsyncData(async () => {
    if (!organizationId) return [];
    const data = await listApplicationTemplates(organizationId);
    return data || [];
  }, [organizationId]);
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
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
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
                      <Typography variant="body2" fontWeight={500}>
                        {template.name}
                      </Typography>
                      {template.description && (
                        <Typography variant="caption" color="text.secondary">
                          {template.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>{template.credential_template_id || '—'}</TableCell>
                    <TableCell align="right">{(template.form_fields || []).length}</TableCell>
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
                      <Tooltip title="Configure required checks">
                        <IconButton
                          size="small"
                          color="secondary"
                          onClick={() => checksDialog.open(template)}
                        >
                          <RuleIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('applicationTemplatesPage.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/templates/applications/${template.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('applicationTemplatesPage.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/templates/applications/${template.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
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

export default ApplicationTemplatesPage;
