import { loadScopedCatalog } from '../../../services/loadScopedCatalog';
/**
 * Organization Defaults Section
 * 
 * Configure default resources for new flows and operations:
 * - Default Trust Profile
 * - Default Presentation Policy
 * - Default Credential Template
 */

import { useState, useEffect, useId, useRef } from 'react';
import {
  Paper,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Box,
  Alert,
  CircularProgress,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import { useTranslation } from 'react-i18next';

import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  getOrganizationDefaults,
  updateOrganizationDefaults,
} from '../../../services/organizationsApi';
import {
  listTrustProfiles,
  listPresentationPolicies,
  listCredentialTemplates,
} from '../../../services/presentationPolicyApi';

const SHOULD_LOG_ORG_DEFAULTS_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';
const EMPTY_DEFAULTS = {
  default_trust_profile_id: '',
  default_policy_id: '',
  default_template_id: '',
};

function logOrgDefaultsError(message, error) {
  if (SHOULD_LOG_ORG_DEFAULTS_DIAGNOSTICS) {
    console.error(message, error);
  }
}

function normalizeDefaults(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Organization defaults returned an invalid response.');
  }

  return Object.fromEntries(Object.keys(EMPTY_DEFAULTS).map((field) => {
    const value = data[field];
    if (value !== null && (typeof value !== 'string' || !value.trim())) {
      throw new Error('Organization defaults returned an invalid resource ID.');
    }
    return [field, value ?? ''];
  }));
}

function isActiveResource(resource) {
  return String(resource.status).toLowerCase() === 'active';
}

function DefaultResourceSelect({ label, value, options, disabled, onChange, noneLabel, unavailableLabel }) {
  const inputId = useId();
  const unavailable = value && !options.some(option => option.id === value);

  return (
    <FormControl fullWidth disabled={disabled}>
      <InputLabel id={`${inputId}-label`} shrink>{label}</InputLabel>
      <Select id={inputId} labelId={`${inputId}-label`} label={label} value={value} onChange={onChange} displayEmpty>
        <MenuItem value=""><em>{noneLabel}</em></MenuItem>
        {unavailable && <MenuItem value={value} disabled>{unavailableLabel}</MenuItem>}
        {options.map(option => (
          <MenuItem key={option.id} value={option.id}>{option.name}</MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}

/**
 * Organization Defaults Section Component
 */
export function OrgDefaultsSection() {
  const { activeOrgId } = useConsole();
  // A selection change must discard both loaded data and unsaved edits immediately.
  return <OrganizationDefaultsForm key={activeOrgId || 'no-organization'} organizationId={activeOrgId} />;
}

function OrganizationDefaultsForm({ organizationId }) {
  const { t } = useTranslation('console');
  const { can } = usePermissions();
  const canEdit = can('organization', 'edit');
  const requestGeneration = useRef(0);
  const savePending = useRef(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [loading, setLoading] = useState(Boolean(organizationId));
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(false);
  const [success, setSuccess] = useState(false);

  // Defaults state
  const [defaults, setDefaults] = useState(EMPTY_DEFAULTS);
  const [savedDefaults, setSavedDefaults] = useState(EMPTY_DEFAULTS);

  // Available resources
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [templates, setTemplates] = useState([]);
  const resources = [
    { field: 'default_trust_profile_id', label: 'defaultTrustProfile', options: trustProfiles },
    { field: 'default_policy_id', label: 'defaultPresentationPolicy', options: policies },
    { field: 'default_template_id', label: 'defaultCredentialTemplate', options: templates },
  ];
  const hasUnavailableDefault = resources.some(({ field, options }) => (
    defaults[field] && !options.some(option => option.id === defaults[field])
  ));
  const hasChanges = Object.keys(EMPTY_DEFAULTS).some(field => defaults[field] !== savedDefaults[field]);

  useEffect(() => {
    const generation = ++requestGeneration.current;
    const controller = new AbortController();
    const isCurrentRequest = () => requestGeneration.current === generation;

    setLoading(Boolean(organizationId));
    setLoaded(false);
    setLoadError(false);
    setSaveError(false);
    setSaving(false);
    savePending.current = false;
    setSuccess(false);
    setDefaults(EMPTY_DEFAULTS);
    setSavedDefaults(EMPTY_DEFAULTS);
    setTrustProfiles([]);
    setPolicies([]);
    setTemplates([]);

    async function loadData() {
      if (!organizationId) return;

      try {
        // Load defaults and available resources in parallel
        const [defaultsData, profilesData, policiesData, templatesData] = await Promise.all([
          getOrganizationDefaults(organizationId),
          loadScopedCatalog(listTrustProfiles, organizationId, { signal: controller.signal }),
          loadScopedCatalog(listPresentationPolicies, organizationId, { signal: controller.signal }),
          loadScopedCatalog(listCredentialTemplates, organizationId, { signal: controller.signal }),
        ]);

        if (!isCurrentRequest()) return;

        const initialDefaults = normalizeDefaults(defaultsData);
        setDefaults(initialDefaults);
        setSavedDefaults(initialDefaults);
        setTrustProfiles(profilesData.filter(isActiveResource));
        setPolicies(policiesData.filter(isActiveResource));
        setTemplates(templatesData.filter(isActiveResource));
        setLoaded(true);
      } catch (err) {
        if (!isCurrentRequest()) return;
        logOrgDefaultsError('Failed to load org defaults:', err);
        setLoadError(true);
      } finally {
        if (isCurrentRequest()) setLoading(false);
      }
    }

    loadData();
    return () => {
      requestGeneration.current += 1;
      controller.abort();
    };
  }, [organizationId, loadAttempt]);

  useEffect(() => {
    if (!success) return;
    const timeout = setTimeout(() => setSuccess(false), 3000);
    return () => clearTimeout(timeout);
  }, [success]);

  const handleSave = async () => {
    if (!organizationId || !loaded || loading || savePending.current || !canEdit || hasUnavailableDefault || !hasChanges) return;

    const generation = requestGeneration.current;
    const isCurrentRequest = () => requestGeneration.current === generation;
    savePending.current = true;
    setSaving(true);
    setSaveError(false);
    setSuccess(false);

    try {
      const patch = Object.fromEntries(Object.keys(EMPTY_DEFAULTS)
        .filter(field => defaults[field] !== savedDefaults[field])
        .map(field => [field, defaults[field] || null]));
      const updated = normalizeDefaults(await updateOrganizationDefaults(organizationId, patch));
      if (isCurrentRequest()) {
        setDefaults(updated);
        setSavedDefaults(updated);
        setSuccess(true);
      }
    } catch (err) {
      if (!isCurrentRequest()) return;
      logOrgDefaultsError('Failed to save org defaults:', err);
      setSaveError(true);
    } finally {
      if (isCurrentRequest()) {
        savePending.current = false;
        setSaving(false);
      }
    }
  };

  const handleChange = (field, value) => {
    if (!loaded || loading || saving || !canEdit) return;
    setSuccess(false);
    setDefaults(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  if (loading) {
    return (
      <Paper sx={{ p: 3, mb: 3, textAlign: 'center' }}>
        <CircularProgress aria-label={t('common.loading', { ns: 'common' })} />
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        {t('org.defaultsSection.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('org.defaultsSection.description')}
      </Typography>

      {!organizationId && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {t('org.defaultsSection.messages.organizationRequired', {
            defaultValue: 'Select an organization before configuring defaults.',
          })}
        </Alert>
      )}

      {loadError && (
        <Alert
          severity="error"
          sx={{ mb: 2 }}
          action={
            <Button color="inherit" size="small" onClick={() => setLoadAttempt(attempt => attempt + 1)}>
              {t('actions.retry', { ns: 'common' })}
            </Button>
          }
        >
          {t('org.defaultsSection.messages.loadFailed')}
        </Alert>
      )}

      {saveError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {t('org.defaultsSection.messages.saveFailed')}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {t('org.defaultsSection.messages.saveSuccess')}
        </Alert>
      )}

      {loaded && organizationId && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {hasUnavailableDefault && (
            <Alert severity="warning">
              {t('org.defaultsSection.messages.unavailableDefault', {
                defaultValue: 'One or more saved defaults are unavailable. Choose an active resource or clear the selection before saving.',
              })}
            </Alert>
          )}

          {resources.map(({ field, label, options }) => (
            <DefaultResourceSelect
              key={field}
              label={t(`org.defaultsSection.fields.${label}`)}
              value={defaults[field]}
              options={options}
              disabled={!canEdit || saving}
              onChange={(event) => handleChange(field, event.target.value)}
              noneLabel={t('org.defaultsSection.values.noneManualSelection')}
              unavailableLabel={t('org.defaultsSection.values.unavailable', { defaultValue: 'Unavailable resource' })}
            />
          ))}

          {canEdit && (
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 1 }}>
              <Button
                variant="contained"
                startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
                onClick={handleSave}
                disabled={saving || hasUnavailableDefault || !hasChanges}
              >
                {saving ? t('org.defaultsSection.actions.saving') : t('org.defaultsSection.actions.save')}
              </Button>
            </Box>
          )}
        </Box>
      )}
    </Paper>
  );
}

export default OrgDefaultsSection;
