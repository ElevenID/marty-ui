/**
 * Application Templates Page
 * 
 * Manages application templates - forms and workflows for credential applications.
 */

import { useState, useEffect } from 'react';
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
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

function ApplicationTemplatesPage() {
  const { t } = useTranslation('console');
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const getTemplatesTabs = () => [
    { label: t('templates.credentialTemplates'), path: '/console/templates/credentials' },
    { label: t('templates.applicationTemplates'), path: '/console/templates/applications' },
  ];

  const getBreadcrumbs = () => [
    { label: t('applicationTemplatesPage.breadcrumbs.console'), path: '/console' },
    { label: t('applicationTemplatesPage.breadcrumbs.templates'), path: '/console/templates' },
    { label: t('applicationTemplatesPage.breadcrumbs.applicationTemplates'), path: '/console/templates/applications' },
  ];

  useEffect(() => {
    // TODO: Fetch application templates from API
    const loadTemplates = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setTemplates([
          {
            id: 'at-1',
            name: 'Standard Identity Application',
            credentialTemplate: 'EU Digital Identity Credential',
            fields: 8,
            requiresDocuments: true,
            requiresVerification: true,
            applicationsCount: 1250,
            status: 'active',
            updatedAt: '2026-02-06T10:30:00Z',
          },
          {
            id: 'at-2',
            name: 'Express mDL Application',
            credentialTemplate: 'Mobile Driving License',
            fields: 5,
            requiresDocuments: true,
            requiresVerification: false,
            applicationsCount: 430,
            status: 'active',
            updatedAt: '2026-02-05T14:20:00Z',
          },
        ]);
      } catch (err) {
        setError(t('applicationTemplatesPage.failedToLoad'));
      } finally {
        setLoading(false);
      }
    };
    loadTemplates();
  }, []);

  return (
    <ResourcePage
      title={t('applicationTemplatesPage.title')}
      description={t('applicationTemplatesPage.description')}
      resourceName={t('applicationTemplatesPage.resourceName')}
      buildPath="/console/templates/applications/new"
      newPath="/console/templates/applications/new?mode=advanced"
      tabs={getTemplatesTabs()}
      breadcrumbs={getBreadcrumbs()}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
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
                <TableCell>{t('applicationTemplatesPage.tableHeaders.requirements')}</TableCell>
                <TableCell align="right">{t('applicationTemplatesPage.tableHeaders.applications')}</TableCell>
                <TableCell>{t('applicationTemplatesPage.tableHeaders.status')}</TableCell>
                <TableCell>{t('applicationTemplatesPage.tableHeaders.lastUpdated')}</TableCell>
                <TableCell align="right">{t('applicationTemplatesPage.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {templates.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8}>
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
                    </TableCell>
                    <TableCell>{template.credentialTemplate}</TableCell>
                    <TableCell align="right">{template.fields}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5 }}>
                        {template.requiresDocuments && (
                          <Chip label={t('applicationTemplatesPage.requirements.documents')} size="small" variant="outlined" />
                        )}
                        {template.requiresVerification && (
                          <Chip label={t('applicationTemplatesPage.requirements.verification')} size="small" variant="outlined" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell align="right">
                      {template.applicationsCount.toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <StatusChip status={template.status} />
                    </TableCell>
                    <TableCell>
                      {new Date(template.updatedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('applicationTemplatesPage.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/templates/applications/${template.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('applicationTemplatesPage.actions.duplicate')}>
                        <IconButton size="small">
                          <ContentCopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('applicationTemplatesPage.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/templates/applications/${template.id}/edit`}
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
  );
}

export default ApplicationTemplatesPage;
