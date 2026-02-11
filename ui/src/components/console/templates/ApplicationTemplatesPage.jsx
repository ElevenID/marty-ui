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

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

const TEMPLATES_TABS = [
  { label: 'Credential Templates', path: '/console/templates/credentials' },
  { label: 'Application Templates', path: '/console/templates/applications' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Templates', path: '/console/templates' },
  { label: 'Application Templates', path: '/console/templates/applications' },
];

function ApplicationTemplatesPage() {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
        setError('Failed to load application templates');
      } finally {
        setLoading(false);
      }
    };
    loadTemplates();
  }, []);

  return (
    <ResourcePage
      title="Application Templates"
      description="Define application forms and workflows that applicants use to request credentials."
      resourceName="Application Template"
      buildPath="/console/templates/applications/new"
      newPath="/console/templates/applications/new?mode=advanced"
      tabs={TEMPLATES_TABS}
      breadcrumbs={BREADCRUMBS}
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
                <TableCell>Name</TableCell>
                <TableCell>Credential Type</TableCell>
                <TableCell align="right">Fields</TableCell>
                <TableCell>Requirements</TableCell>
                <TableCell align="right">Applications</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Updated</TableCell>
                <TableCell align="right">Actions</TableCell>
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
                          <Chip label="Documents" size="small" variant="outlined" />
                        )}
                        {template.requiresVerification && (
                          <Chip label="ID Verify" size="small" variant="outlined" />
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
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/templates/applications/${template.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Duplicate">
                        <IconButton size="small">
                          <ContentCopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton
                          component={Link}
                          to={`/console/templates/applications/${template.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Preview Application Form">
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
