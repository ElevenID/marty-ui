/**
 * Credential Templates Page
 * 
 * Manages credential templates - schema definitions for issuable credentials.
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
  Button,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import { Link } from 'react-router-dom';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

const TEMPLATES_TABS = [
  { label: 'Credential Templates', path: '/console/templates/credentials' },
  { label: 'Application Templates', path: '/console/templates/applications' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Templates', path: '/console/templates' },
  { label: 'Credential Templates', path: '/console/templates/credentials' },
];

/**
 * Artifacts status indicator
 */
function ArtifactsStatus({ hasArtifacts, validated }) {
  if (!hasArtifacts) {
    return (
      <Tooltip title="Missing required artifacts">
        <Chip 
          icon={<WarningIcon />} 
          label="Missing Artifacts" 
          color="warning" 
          size="small" 
        />
      </Tooltip>
    );
  }
  
  if (!validated) {
    return (
      <Tooltip title="Artifacts not validated">
        <Chip label="Not Validated" size="small" variant="outlined" />
      </Tooltip>
    );
  }
  
  return (
    <Tooltip title="All artifacts validated">
      <Chip 
        icon={<CheckCircleIcon />} 
        label="Valid" 
        color="success" 
        size="small" 
      />
    </Tooltip>
  );
}

function CredentialTemplatesPage() {
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
          },
        ]);
      } catch (err) {
        setError('Failed to load credential templates');
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
      title="Credential Templates"
      description="Define schemas and formats for credentials your organization can issue."
      resourceName="Template"
      buildPath="/console/templates/credentials/new"
      newPath="/console/templates/credentials/new?mode=advanced"
      tabs={TEMPLATES_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {missingArtifactsCount > 0 && (
        <Alert 
          severity="warning" 
          sx={{ mb: 3 }}
          action={
            <Button color="inherit" size="small">
              Validate All
            </Button>
          }
        >
          {missingArtifactsCount} template(s) have missing or unvalidated artifacts.
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
                <TableCell>Name</TableCell>
                <TableCell>Format</TableCell>
                <TableCell>Version</TableCell>
                <TableCell align="right">Claims</TableCell>
                <TableCell>Artifacts</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Updated</TableCell>
                <TableCell align="right">Actions</TableCell>
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
                      <StatusChip status={template.status} />
                    </TableCell>
                    <TableCell>
                      {new Date(template.updatedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/templates/credentials/${template.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton
                          component={Link}
                          to={`/console/templates/credentials/${template.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
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
