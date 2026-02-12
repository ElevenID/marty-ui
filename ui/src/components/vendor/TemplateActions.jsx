/**
 * Template Manager Component
 *
 * UI for publishing, cloning, and previewing credential templates.
 * Handles template marketplace browsing and publishing workflow.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
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

const API_URL = import.meta.env.VITE_API_URL || '';

export function PublishDialog({ open, onClose, configId, onPublished }) {
  const { t } = useTranslation('vendor');
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
        throw new Error(data.detail || t('templateActions.publishDialog.publishFailed'));
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
      <DialogTitle>{t('templateActions.publishDialog.title')}</DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Alert severity="info" sx={{ mb: 3 }}>
          {t('templateActions.publishDialog.infoMessage')}
        </Alert>

        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>{t('templateActions.publishDialog.visibilityLabel')}</InputLabel>
          <Select
            value={visibility}
            onChange={(e) => setVisibility(e.target.value)}
            label={t('templateActions.publishDialog.visibilityLabel')}
          >
            <MenuItem value="private">{t('templateActions.publishDialog.visibility.private')}</MenuItem>
            <MenuItem value="organization">{t('templateActions.publishDialog.visibility.organization')}</MenuItem>
            <MenuItem value="public">{t('templateActions.publishDialog.visibility.public')}</MenuItem>
          </Select>
        </FormControl>

        <TextField
          fullWidth
          multiline
          rows={3}
          label={t('templateActions.publishDialog.changeDescriptionLabel')}
          placeholder={t('templateActions.publishDialog.changeDescriptionPlaceholder')}
          value={changeDescription}
          onChange={(e) => setChangeDescription(e.target.value)}
          sx={{ mb: 2 }}
        />

        <Typography variant="caption" color="textSecondary">
          {t('templateActions.publishDialog.versionNote')}
        </Typography>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={publishing}>
          {t('templateActions.publishDialog.cancelButton')}
        </Button>
        <Button
          variant="contained"
          onClick={handlePublish}
          disabled={publishing}
          startIcon={publishing ? <CircularProgress size={16} /> : <PublishIcon />}
        >
          {t('templateActions.publishDialog.publishButton')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function PreviewDialog({ open, onClose, configId, configData }) {
  const { t } = useTranslation('vendor');
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
        throw new Error(t('templateActions.previewDialog.validateFailed'));
      }

      const data = await response.json();
      setValidationResult(data);
    } catch (err) {
      setValidationResult({
        valid: false,
        errors: { _general: [t('templateActions.previewDialog.validateError', { error: err.message })] },
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
        {t('templateActions.previewDialog.title')}
        <IconButton
          onClick={onClose}
          sx={{ position: 'absolute', right: 8, top: 8 }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 3 }}>
          {t('templateActions.previewDialog.infoMessage')}
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
                ? t('templateActions.previewDialog.validationSuccess')
                : t('templateActions.previewDialog.validationErrors', { count: validationResult.validation_summary?.invalid_fields || 0 })}
            </Alert>

            {validationResult.missing_required_fields?.length > 0 && (
              <Alert severity="warning" sx={{ mt: 1 }}>
                {t('templateActions.previewDialog.missingFields', { fields: validationResult.missing_required_fields.join(', ') })}
              </Alert>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('templateActions.previewDialog.closeButton')}</Button>
        <Button
          variant="contained"
          onClick={handleValidate}
          disabled={validating}
          startIcon={validating ? <CircularProgress size={16} /> : <PreviewIcon />}
        >
          {t('templateActions.previewDialog.validateButton')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function VersionHistoryDialog({ open, onClose, configId }) {
  const { t } = useTranslation('vendor');
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
      <DialogTitle>{t('templateActions.versionHistoryDialog.title')}</DialogTitle>
      <DialogContent>
        {loading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : versions.length === 0 ? (
          <Alert severity="info">{t('templateActions.versionHistoryDialog.noHistory')}</Alert>
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
                          {version.change_description || t('templateActions.versionHistoryDialog.noDescription')}
                        </Typography>
                      </Box>
                    }
                    secondary={
                      version.created_at
                        ? new Date(version.created_at).toLocaleString()
                        : t('templateActions.versionHistoryDialog.unknownDate')
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
        <Button onClick={onClose}>{t('templateActions.versionHistoryDialog.closeButton')}</Button>
      </DialogActions>
    </Dialog>
  );
}

export function TemplateActions({ configId, configData, onStatusChange }) {
  const { t } = useTranslation('vendor');
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
        {isPublished ? t('templateActions.unpublishButton') : t('templateActions.publishButton')}
      </Button>

      <Button
        variant="outlined"
        startIcon={<PreviewIcon />}
        onClick={() => setPreviewDialogOpen(true)}
      >
        {t('templateActions.previewButton')}
      </Button>

      <Button
        variant="outlined"
        startIcon={<HistoryIcon />}
        onClick={() => setVersionDialogOpen(true)}
      >
        {t('templateActions.historyButton')}
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
