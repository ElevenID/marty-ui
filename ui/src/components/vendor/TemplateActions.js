/**
 * Template Manager Component
 *
 * UI for publishing, cloning, and previewing credential templates.
 * Handles template marketplace browsing and publishing workflow.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Chip,
  Typography,
  Grid,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Divider,
  CircularProgress,
} from '@mui/material';
import PublishIcon from '@mui/icons-material/Publish';
import UnpublishedIcon from '@mui/icons-material/Unpublished';
import PreviewIcon from '@mui/icons-material/Preview';
import HistoryIcon from '@mui/icons-material/History';
import CloseIcon from '@mui/icons-material/Close';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';

const API_URL = process.env.REACT_APP_API_URL || '';

export function PublishDialog({ open, onClose, configId, onPublished }) {
  const [visibility, setVisibility] = useState('private');
  const [changeDescription, setChangeDescription] = useState('');
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState(null);

  const handlePublish = async () => {
    setPublishing(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${configId.orgId}/credential-types/${configId.typeId}/publish?visibility=${visibility}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ change_description: changeDescription }),
        }
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to publish template');
      }

      const data = await response.json();
      onPublished(data.credential_type);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setPublishing(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Publish Template</DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Alert severity="info" sx={{ mb: 3 }}>
          Publishing makes this template available for applicants to use.
        </Alert>

        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Visibility</InputLabel>
          <Select
            value={visibility}
            onChange={(e) => setVisibility(e.target.value)}
            label="Visibility"
          >
            <MenuItem value="private">Private - Only your organization</MenuItem>
            <MenuItem value="organization">Organization - Members only</MenuItem>
            <MenuItem value="public">Public - Available to all organizations</MenuItem>
          </Select>
        </FormControl>

        <TextField
          fullWidth
          multiline
          rows={3}
          label="Change Description (Optional)"
          placeholder="Describe what's new in this version..."
          value={changeDescription}
          onChange={(e) => setChangeDescription(e.target.value)}
          sx={{ mb: 2 }}
        />

        <Typography variant="caption" color="textSecondary">
          Publishing will increment the template version number and create a version history entry.
        </Typography>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={publishing}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handlePublish}
          disabled={publishing}
          startIcon={publishing ? <CircularProgress size={16} /> : <PublishIcon />}
        >
          Publish
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function PreviewDialog({ open, onClose, configId, configData }) {
  const [testData, setTestData] = useState({});
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);

  const handleFieldChange = (fieldName, value) => {
    setTestData((prev) => ({ ...prev, [fieldName]: value }));
  };

  const handleValidate = async () => {
    setValidating(true);
    setValidationResult(null);

    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${configId.orgId}/credential-types/${configId.typeId}/preview`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(testData),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to validate');
      }

      const data = await response.json();
      setValidationResult(data);
    } catch (err) {
      setValidationResult({
        valid: false,
        errors: { _general: ['Failed to validate: ' + err.message] },
      });
    } finally {
      setValidating(false);
    }
  };

  const requiredFields = configData?.required_fields || [];
  const optionalFields = configData?.optional_fields || [];
  const allFields = [...requiredFields, ...optionalFields];

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        Preview & Test Template
        <IconButton
          onClick={onClose}
          sx={{ position: 'absolute', right: 8, top: 8 }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 3 }}>
          Fill out the form below to test validation rules before publishing.
        </Alert>

        <Grid container spacing={2}>
          {allFields.map((field) => (
            <Grid item xs={12} sm={6} key={field}>
              <TextField
                fullWidth
                label={field.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                required={requiredFields.includes(field)}
                value={testData[field] || ''}
                onChange={(e) => handleFieldChange(field, e.target.value)}
                error={validationResult?.errors?.[field]}
                helperText={validationResult?.errors?.[field]?.[0]}
              />
            </Grid>
          ))}
        </Grid>

        {validationResult && (
          <Box sx={{ mt: 3 }}>
            <Alert
              severity={validationResult.valid ? 'success' : 'error'}
              icon={validationResult.valid ? <CheckCircleIcon /> : <ErrorIcon />}
            >
              {validationResult.valid
                ? 'All fields passed validation!'
                : `Found ${validationResult.validation_summary?.invalid_fields || 0} validation errors`}
            </Alert>

            {validationResult.missing_required_fields?.length > 0 && (
              <Alert severity="warning" sx={{ mt: 1 }}>
                Missing required fields: {validationResult.missing_required_fields.join(', ')}
              </Alert>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        <Button
          variant="contained"
          onClick={handleValidate}
          disabled={validating}
          startIcon={validating ? <CircularProgress size={16} /> : <PreviewIcon />}
        >
          Validate
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function VersionHistoryDialog({ open, onClose, configId }) {
  const [versions, setVersions] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchVersions = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${configId.orgId}/credential-types/${configId.typeId}/versions`,
        { credentials: 'include' }
      );

      if (response.ok) {
        const data = await response.json();
        setVersions(data.versions || []);
      }
    } catch (err) {
      console.error('Failed to fetch versions:', err);
    } finally {
      setLoading(false);
    }
  }, [configId]);

  useEffect(() => {
    if (open && configId) {
      fetchVersions();
    }
  }, [open, configId, fetchVersions]);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Version History</DialogTitle>
      <DialogContent>
        {loading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : versions.length === 0 ? (
          <Alert severity="info">No version history available yet.</Alert>
        ) : (
          <List>
            {versions.map((version) => (
              <React.Fragment key={version.version_number}>
                <ListItem>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1}>
                        <Chip
                          label={`v${version.version_number}`}
                          size="small"
                          color="primary"
                        />
                        <Typography variant="body2">
                          {version.change_description || 'No description'}
                        </Typography>
                      </Box>
                    }
                    secondary={
                      version.created_at
                        ? new Date(version.created_at).toLocaleString()
                        : 'Unknown date'
                    }
                  />
                </ListItem>
                <Divider />
              </React.Fragment>
            ))}
          </List>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

export function TemplateActions({ configId, configData, onStatusChange }) {
  const [publishDialogOpen, setPublishDialogOpen] = useState(false);
  const [previewDialogOpen, setPreviewDialogOpen] = useState(false);
  const [versionDialogOpen, setVersionDialogOpen] = useState(false);
  const [unpublishing, setUnpublishing] = useState(false);

  const handleUnpublish = async () => {
    setUnpublishing(true);
    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${configId.orgId}/credential-types/${configId.typeId}/unpublish`,
        {
          method: 'POST',
          credentials: 'include',
        }
      );

      if (response.ok) {
        const data = await response.json();
        onStatusChange(data.credential_type);
      }
    } catch (err) {
      console.error('Failed to unpublish:', err);
    } finally {
      setUnpublishing(false);
    }
  };

  const isPublished = configData?.is_published;

  return (
    <Box display="flex" gap={1} flexWrap="wrap">
      <Button
        variant={isPublished ? 'outlined' : 'contained'}
        color={isPublished ? 'warning' : 'primary'}
        startIcon={isPublished ? <UnpublishedIcon /> : <PublishIcon />}
        onClick={isPublished ? handleUnpublish : () => setPublishDialogOpen(true)}
        disabled={unpublishing}
      >
        {isPublished ? 'Unpublish' : 'Publish'}
      </Button>

      <Button
        variant="outlined"
        startIcon={<PreviewIcon />}
        onClick={() => setPreviewDialogOpen(true)}
      >
        Preview & Test
      </Button>

      <Button
        variant="outlined"
        startIcon={<HistoryIcon />}
        onClick={() => setVersionDialogOpen(true)}
      >
        History
      </Button>

      {configData?.is_published && (
        <Chip
          label={`v${configData.template_version || 1}`}
          color="primary"
          size="small"
          sx={{ ml: 1 }}
        />
      )}

      {configData?.visibility && (
        <Chip
          label={configData.visibility}
          size="small"
          variant="outlined"
          sx={{ ml: 1 }}
        />
      )}

      <PublishDialog
        open={publishDialogOpen}
        onClose={() => setPublishDialogOpen(false)}
        configId={configId}
        onPublished={onStatusChange}
      />

      <PreviewDialog
        open={previewDialogOpen}
        onClose={() => setPreviewDialogOpen(false)}
        configId={configId}
        configData={configData}
      />

      <VersionHistoryDialog
        open={versionDialogOpen}
        onClose={() => setVersionDialogOpen(false)}
        configId={configId}
      />
    </Box>
  );
}
