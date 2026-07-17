/**
 * Trust Profile Edit Page
 *
 * Allows editing the basic configuration of an existing trust profile:
 * name, description, framework type, supported credential formats, and status.
 */

import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import {
  Alert,
  Box,
  Breadcrumbs,
  Button,
  Checkbox,
  CircularProgress,
  FormControl,
  FormControlLabel,
  FormGroup,
  FormHelperText,
  InputLabel,
  Link,
  MenuItem,
  Paper,
  Select,
  Skeleton,
  TextField,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import SaveIcon from '@mui/icons-material/Save';
import { useTranslation } from 'react-i18next';

import { useAsyncData } from '../../../hooks/useAsyncData';
import { getTrustProfile, updateTrustProfile } from '../../../services/presentationPolicyApi';
import {
  TRUST_PROFILE_SUPPORTED_FORMATS,
  getSupportedFormatsForFramework,
  isFrameworkFormatSelectionLocked,
} from './trustProfileFormatCatalog';

const FRAMEWORK_TYPES = [
  { value: 'icao', label: 'ICAO' },
  { value: 'aamva', label: 'AAMVA' },
  { value: 'eudi', label: 'EUDI' },
  { value: 'custom', label: 'Custom' },
];

const STATUS_OPTIONS = [
  { value: 'active', label: 'Active' },
  { value: 'draft', label: 'Draft' },
  { value: 'archived', label: 'Archived' },
];

export function TrustProfileEditPage() {
  const { t } = useTranslation('console');
  const { id } = useParams();
  const navigate = useNavigate();

  const { data: profile, loading: loadingProfile, error: loadError } = useAsyncData(
    () => (id ? getTrustProfile(id) : Promise.resolve(null)),
    [id]
  );

  const [form, setForm] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  // Seed form state once profile is loaded
  useEffect(() => {
    if (profile && !form) {
      const frameworkType = profile.framework || profile.profile_type || 'custom';
      setForm({
        name: profile.name || '',
        description: profile.description || '',
        framework_type: frameworkType,
        supported_formats: getSupportedFormatsForFramework(frameworkType, profile.supported_formats),
        status: profile.status || 'active',
      });
    }
  }, [profile, form]);

  const handleFormatToggle = useCallback((fmt) => {
    setForm((prev) => {
      if (!prev || isFrameworkFormatSelectionLocked(prev.framework_type)) {
        return prev;
      }

      const current = getSupportedFormatsForFramework('custom', prev.supported_formats);
      return {
        ...prev,
        supported_formats: current.includes(fmt)
          ? current.filter((f) => f !== fmt)
          : [...current, fmt],
      };
    });
  }, []);

  const handleFrameworkChange = useCallback((nextFrameworkType) => {
    setForm((prev) => ({
      ...prev,
      framework_type: nextFrameworkType,
      supported_formats: getSupportedFormatsForFramework(nextFrameworkType, prev?.supported_formats),
    }));
  }, []);

  const handleSave = useCallback(async () => {
    if (!form) return;
    setSaving(true);
    setSaveError(null);
    try {
      await updateTrustProfile(id, form);
      navigate(`/console/org/trust/profiles/${id}`);
    } catch (err) {
      setSaveError(err?.message || t('trust.trustProfileEdit.saveFailed', 'Failed to save trust profile.'));
      setSaving(false);
    }
  }, [form, id, navigate, t]);

  if (loadingProfile || (!form && !loadError)) {
    return (
      <Box sx={{ py: 4 }}>
        <Skeleton variant="text" width={300} height={40} />
        <Skeleton variant="rectangular" height={400} sx={{ mt: 2 }} />
      </Box>
    );
  }

  if (loadError || !profile) {
    return (
      <Box sx={{ py: 4 }}>
        <Alert severity="error">
          {loadError?.message || t('trust.trustProfileEdit.notFound', 'Trust profile not found.')}
        </Alert>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/profiles')}
          sx={{ mt: 2 }}
        >
          {t('trust.trustProfileEdit.backToProfiles', 'Back to Profiles')}
        </Button>
      </Box>
    );
  }

  const supportedFormats = TRUST_PROFILE_SUPPORTED_FORMATS.map((format) => ({
    ...format,
    label: t(format.labelKey, { defaultValue: format.value }),
  }));
  const supportedFormatsLabel = t('wizards.trustProfile.basicsStep.fields.supportedFormats', 'Supported Credential Formats').replace(/\s*\*$/, '');
  const formatSelectionLocked = isFrameworkFormatSelectionLocked(form.framework_type);

  return (
    <Box>
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link component={RouterLink} to="/console" underline="hover" color="inherit">
          {t('trust.breadcrumbs.console', 'Console')}
        </Link>
        <Link component={RouterLink} to="/console/org/trust" underline="hover" color="inherit">
          {t('trust.breadcrumbs.trust', 'Trust')}
        </Link>
        <Link component={RouterLink} to="/console/org/trust/profiles" underline="hover" color="inherit">
          {t('trust.breadcrumbs.trustProfiles', 'Trust Profiles')}
        </Link>
        <Link component={RouterLink} to={`/console/org/trust/profiles/${id}`} underline="hover" color="inherit">
          {profile.name}
        </Link>
        <Typography color="text.primary">
          {t('trust.trustProfileEdit.breadcrumbEdit', 'Edit')}
        </Typography>
      </Breadcrumbs>

      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          {t('trust.trustProfileEdit.title', 'Edit Trust Profile')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('trust.trustProfileEdit.subtitle', 'Update the name, description, framework, and accepted credential formats for this trust profile.')}
        </Typography>
      </Box>

      {saveError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {saveError}
        </Alert>
      )}

      <Paper sx={{ p: 3, mb: 3 }}>
        {/* Name */}
        <TextField
          fullWidth
          required
          label={t('wizards.trustProfile.basicsStep.fields.name', 'Profile Name')}
          value={form.name}
          onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
          sx={{ mb: 3 }}
          helperText={t('wizards.trustProfile.basicsStep.helpers.name', 'A descriptive name for this trust configuration.')}
          slotProps={{ htmlInput: { 'data-testid': 'edit.trustProfile.name' } }}
        />

        {/* Description */}
        <TextField
          fullWidth
          multiline
          rows={3}
          label={t('wizards.trustProfile.basicsStep.fields.description', 'Description')}
          value={form.description}
          onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
          sx={{ mb: 3 }}
          helperText={t('wizards.trustProfile.basicsStep.helpers.description', 'Optional description of the trust policy intent.')}
          slotProps={{ htmlInput: { 'data-testid': 'edit.trustProfile.description' } }}
        />

        {/* Framework Type */}
        <FormControl fullWidth sx={{ mb: 3 }} data-testid="edit.trustProfile.frameworkTypeField">
          <InputLabel>{t('wizards.trustProfile.basicsStep.fields.frameworkType', 'Framework Type')}</InputLabel>
          <Select
            value={form.framework_type}
            onChange={(e) => handleFrameworkChange(e.target.value)}
            label={t('wizards.trustProfile.basicsStep.fields.frameworkType', 'Framework Type')}
            data-testid="edit.trustProfile.frameworkType"
          >
            {FRAMEWORK_TYPES.map((type) => (
              <MenuItem key={type.value} value={type.value}>
                {type.label}
              </MenuItem>
            ))}
          </Select>
          <FormHelperText>
            {t('wizards.trustProfile.basicsStep.helpers.frameworkType', 'The credential framework this profile aligns to.')}
          </FormHelperText>
        </FormControl>

        {/* Supported Formats */}
        <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            {supportedFormatsLabel}
          </Typography>
          <FormHelperText sx={{ mt: 0, mb: 1 }}>
            {formatSelectionLocked
              ? t('wizards.trustProfile.basicsStep.helpers.supportedFormatsLocked', {
                  defaultValue: 'This framework uses pre-configured credential formats. Choose Custom to edit them.',
                })
              : t('wizards.trustProfile.basicsStep.helpers.supportedFormats', 'Formats this profile will accept during verification.')}
          </FormHelperText>
          <FormGroup>
            {supportedFormats.map((fmt) => (
              <FormControlLabel
                key={fmt.value}
                control={
                  <Checkbox
                    checked={(form.supported_formats || []).includes(fmt.value)}
                    onChange={() => handleFormatToggle(fmt.value)}
                    disabled={formatSelectionLocked}
                    slotProps={{ input: { 'data-testid': `edit.trustProfile.format.${fmt.value}` } }}
                  />
                }
                label={fmt.label}
              />
            ))}
          </FormGroup>
        </FormControl>

        {/* Status */}
        <FormControl fullWidth sx={{ mb: 1 }}>
          <InputLabel>{t('trust.trustProfileEdit.statusLabel', 'Status')}</InputLabel>
          <Select
            value={form.status}
            onChange={(e) => setForm((prev) => ({ ...prev, status: e.target.value }))}
            label={t('trust.trustProfileEdit.statusLabel', 'Status')}
            inputProps={{ 'data-testid': 'edit.trustProfile.status' }}
          >
            {STATUS_OPTIONS.map((opt) => (
              <MenuItem key={opt.value} value={opt.value}>
                {opt.label}
              </MenuItem>
            ))}
          </Select>
          <FormHelperText>
            {t('trust.trustProfileEdit.statusHelper', 'Draft profiles are not enforced during verification.')}
          </FormHelperText>
        </FormControl>
      </Paper>

      {/* Actions */}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="contained"
          startIcon={saving ? <CircularProgress size={16} color="inherit" /> : <SaveIcon />}
          onClick={handleSave}
          disabled={saving || !form.name?.trim()}
          data-testid="edit.trustProfile.save"
        >
          {saving
            ? t('trust.trustProfileEdit.saving', 'Saving...')
            : t('trust.trustProfileEdit.saveButton', 'Save Changes')}
        </Button>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate(`/console/org/trust/profiles/${id}`)}
          disabled={saving}
        >
          {t('trust.trustProfileEdit.cancel', 'Cancel')}
        </Button>
      </Box>
    </Box>
  );
}

export default TrustProfileEditPage;
