/**
 * Trust Profile Edit Page
 *
 * Allows editing the basic configuration of an existing trust profile:
 * name, description, framework type, and supported credential formats.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, useLocation, Link as RouterLink } from 'react-router';
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
  LinearProgress,
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
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
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
  { value: 'suspended', label: 'Suspended' },
  { value: 'archived', label: 'Archived' },
];

const STORED_FORMAT_ALIASES = {
  VC_JWT: 'jwt_vc',
  JWT_VC: 'jwt_vc',
  SD_JWT_VC: 'sd_jwt_vc',
  MDOC: 'mdoc',
  JSON_LD: 'ldp_vc',
  LDP_VC: 'ldp_vc',
  VDS_NC: 'vds_nc',
};

function TrustProfileEditContent({ id, organizationId }) {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const startAction = useAsyncActionScope();
  const saveBusy = useRef(false);
  // BrowserRouter changes the history entry before its React transition commits.
  // Keep a completed save from overriding a newer navigation during that gap.
  const browserEntry = useRef(typeof window === 'undefined' ? null : {
    href: window.location.href,
    key: window.history.state?.key,
  });
  const isCurrentView = useCallback((action) => action.isCurrent() && (
    !browserEntry.current || (typeof window !== 'undefined'
      && window.location.href === browserEntry.current.href
      && window.history.state?.key === browserEntry.current.key)
  ), []);
  const validateProfile = useCallback((result, isSaveResponse = false) => {
    if (!result) {
      throw new Error(isSaveResponse
        ? t('trust.trustProfileEdit.invalidResponse')
        : t('trust.trustProfileEdit.notFound', 'Trust profile not found.'));
    }
    if (result.id !== id || result.organization_id !== organizationId) {
      throw new Error(t('trust.trustProfileEdit.scopeMismatch'));
    }
    if (typeof result.name !== 'string'
      || (result.description != null && typeof result.description !== 'string')) {
      throw new Error(t('trust.trustProfileEdit.invalidResponse'));
    }
    const formats = result.supported_formats ?? [];
    if (!Array.isArray(formats)) {
      throw new Error(t('trust.trustProfileEdit.invalidResponse'));
    }
    const storedFormats = formats.map((format) => (
      typeof format === 'string' ? STORED_FORMAT_ALIASES[format.toUpperCase()] : undefined
    ));
    if (storedFormats.includes(undefined) || new Set(storedFormats).size !== storedFormats.length) {
      throw new Error(t('trust.trustProfileEdit.invalidResponse'));
    }
    return { ...result, supported_formats: storedFormats };
  }, [id, organizationId, t]);

  const { data: profile, loading: loadingProfile, error: loadError, reload: reloadProfile } = useAsyncData(
    async () => validateProfile(await getTrustProfile(id)),
    [id, organizationId]
  );

  const [form, setForm] = useState(null);
  const [initialForm, setInitialForm] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  // Seed form state once profile is loaded
  useEffect(() => {
    if (profile && !form) {
      const frameworkType = (profile.framework || profile.profile_type || 'custom').toLowerCase();
      const values = {
        name: profile.name || '',
        description: profile.description || '',
        framework_type: frameworkType,
        // Existing profiles keep their stored formats, including an empty set
        // for machine-identity-only profiles. Presets apply to explicit changes.
        supported_formats: profile.supported_formats,
        status: typeof profile.status === 'string' ? profile.status.toLowerCase() : '',
      };
      setForm(values);
      setInitialForm(values);
    }
  }, [profile, form]);

  const handleFormatToggle = useCallback((fmt) => {
    setForm((prev) => {
      if (!prev || isFrameworkFormatSelectionLocked(prev.framework_type)) {
        return prev;
      }

      const current = prev.supported_formats;
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
      supported_formats: nextFrameworkType === 'custom'
        ? prev.supported_formats
        : getSupportedFormatsForFramework(nextFrameworkType),
    }));
  }, []);

  const handleSave = useCallback(async () => {
    if (!form?.name?.trim() || saveBusy.current) return;
    const action = startAction();
    if (!isCurrentView(action)) return;
    saveBusy.current = true;
    setSaving(true);
    setSaveError(null);
    try {
      const changes = Object.fromEntries(
        Object.entries(form).filter(([key, value]) => (
          key !== 'status' && JSON.stringify(value) !== JSON.stringify(initialForm?.[key])
        ))
      );
      if (Object.keys(changes).length) {
        const result = await action.run(updateTrustProfile, id, changes);
        if (!isCurrentView(action)) return;
        validateProfile(result, true);
      }
      if (!isCurrentView(action)) return;
      navigate(`/console/org/trust/profiles/${encodeURIComponent(id)}`);
    } catch (err) {
      if (isCurrentView(action)) {
        setSaveError(err?.message || t('trust.trustProfileEdit.saveFailed', 'Failed to save trust profile.'));
      }
    } finally {
      if (isCurrentView(action)) {
        saveBusy.current = false;
        setSaving(false);
      }
    }
  }, [form, initialForm, id, navigate, startAction, isCurrentView, t, validateProfile]);

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
        <Button onClick={reloadProfile} sx={{ mt: 2, mr: 2 }}>
          {t('actions.retry', { ns: 'common', defaultValue: 'Retry' })}
        </Button>
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

  const supportedFormats = [
    ...TRUST_PROFILE_SUPPORTED_FORMATS.map((format) => ({
      ...format,
      label: t(format.labelKey, { defaultValue: format.value }),
    })),
    { value: 'vds_nc', label: 'VDS-NC' },
  ];
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
          disabled={saving}
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
          disabled={saving}
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
        <FormControl fullWidth disabled={saving} sx={{ mb: 3 }} data-testid="edit.trustProfile.frameworkTypeField">
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
                    disabled={formatSelectionLocked || saving}
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
            disabled
            displayEmpty
            label={t('trust.trustProfileEdit.statusLabel', 'Status')}
            inputProps={{ 'data-testid': 'edit.trustProfile.status' }}
          >
            {!STATUS_OPTIONS.some((option) => option.value === form.status) && (
              <MenuItem value={form.status}>{t('trust.trustProfileEdit.unknownStatus')}</MenuItem>
            )}
            {STATUS_OPTIONS.map((opt) => (
              <MenuItem key={opt.value} value={opt.value}>
                {opt.value === 'suspended' ? t('trust.trustProfileEdit.suspendedStatus') : opt.label}
              </MenuItem>
            ))}
          </Select>
          <FormHelperText>
            {t('trust.trustProfileEdit.lifecycleStatusHelper', 'Status is managed through profile lifecycle actions, not this edit form.')}
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

export function TrustProfileEditPage() {
  const { t } = useTranslation('console');
  const { id } = useParams();
  const location = useLocation();
  const { activeOrgId } = useConsole();
  const { can, isLoading } = usePermissions();
  const canView = can('trust-profile', 'view');
  const canEdit = can('trust-profile', 'edit');
  if (!activeOrgId) return <Alert severity="error">{t('trust.trustProfileEdit.selectOrganization')}</Alert>;
  if (isLoading) return <LinearProgress />;
  if (!canView || !canEdit) return <Alert severity="error">{t('trust.trustProfileEdit.permissionDenied')}</Alert>;
  const key = JSON.stringify([activeOrgId, id, location.key, location.pathname, location.search, location.hash, canView, canEdit]);
  return <TrustProfileEditContent key={key} id={id} organizationId={activeOrgId} />;
}

export default TrustProfileEditPage;
