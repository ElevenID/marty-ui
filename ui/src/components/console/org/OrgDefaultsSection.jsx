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
  const { can, isLoading } = usePermissions();
  const grants = {
    canView: can('organization', 'view'),
    canEdit: can('organization', 'edit'),
    canViewTrustProfiles: can('trust-profile', 'view'),
    canViewPolicies: can('presentation-policy', 'view'),
    canViewTemplates: can('credential-template', 'view'),
  };
  // Organization and grant changes invalidate drafts, catalogs and pending saves.
  const scopeKey = JSON.stringify([activeOrgId, Boolean(isLoading), ...Object.values(grants)]);
  return (
    <OrganizationDefaultsForm
      key={scopeKey}
      organizationId={activeOrgId}
      permissionsLoading={Boolean(isLoading)}
      {...grants}
    />
  );
}

function OrganizationDefaultsForm({
  organizationId,
  permissionsLoading,
  canView,
  canEdit,
  canViewTrustProfiles,
  canViewPolicies,
  canViewTemplates,
}) {
  const { t } = useTranslation('console');
  const requestGeneration = useRef(0);
  const savePending = useRef(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [loading, setLoading] = useState(Boolean(organizationId && (permissionsLoading || canView)));
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
    { field: 'default_trust_profile_id', label: 'defaultTrustProfile', options: trustProfiles, canView: canViewTrustProfiles },
    { field: 'default_policy_id', label: 'defaultPresentationPolicy', options: policies, canView: canViewPolicies },
    { field: 'default_template_id', label: 'defaultCredentialTemplate', options: templates, canView: canViewTemplates },
  ];
  const hasUnavailableDefault = resources.some(({ field, options, canView: canViewResource }) => (
    canViewResource && defaults[field] && !options.some(option => option.id === defaults[field])
  ));
  const hasUnavailableChange = resources.some(({ field, options }) => (
    defaults[field] !== savedDefaults[field]
      && defaults[field] && !options.some(option => option.id === defaults[field])
  ));
  const hasChanges = Object.keys(EMPTY_DEFAULTS).some(field => defaults[field] !== savedDefaults[field]);

  useEffect(() => {
    const generation = ++requestGeneration.current;
    const controller = new AbortController();
    const isCurrentRequest = () => requestGeneration.current === generation;

    setLoading(Boolean(organizationId && (permissionsLoading || canView)));
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
      if (!organizationId || permissionsLoading || !canView) return;

      try {
        // Defaults and each catalog have separate view grants. A member may
        // clear defaults without permission to select a new catalog resource.
        const [defaultsData, profilesData, policiesData, templatesData] = await Promise.all([
          getOrganizationDefaults(organizationId),
          canViewTrustProfiles ? loadScopedCatalog(listTrustProfiles, organizationId, { signal: controller.signal }) : [],
          canViewPolicies ? loadScopedCatalog(listPresentationPolicies, organizationId, { signal: controller.signal }) : [],
          canViewTemplates ? loadScopedCatalog(listCredentialTemplates, organizationId, { signal: controller.signal }) : [],
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
  }, [organizationId, loadAttempt, permissionsLoading, canView, canViewTrustProfiles, canViewPolicies, canViewTemplates]);

  useEffect(() => {
    if (!success) return;
    const timeout = setTimeout(() => setSuccess(false), 3000);
    return () => clearTimeout(timeout);
  }, [success]);

  const handleSave = async () => {
    if (!organizationId || !loaded || loading || savePending.current || !canEdit || hasUnavailableChange || !hasChanges) return;

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
    const resource = resources.find(resource => resource.field === field);
    if (!resource || (value && !resource.options.some(option => option.id === value))) return;
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

      {organizationId && !canView && !permissionsLoading && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('org.defaultsSection.messages.permissionDenied', {
            defaultValue: 'You do not have permission to view organization defaults.',
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
              {t('org.defaultsSection.messages.unavailableDefaultsPreserved', {
                defaultValue: 'One or more saved defaults are unavailable. They are preserved when you change other defaults. You can replace or clear them if you have permission to edit.',
              })}
            </Alert>
          )}

          {resources.some(resource => !resource.canView) && (
            <Alert severity="info">
              {t('org.defaultsSection.messages.catalogPermissionRequired', {
                defaultValue: 'Some resource details are hidden because you do not have permission to view their catalogs.',
              })}
            </Alert>
          )}

          {resources.map(({ field, label, options, canView: canViewResource }) => (
            <DefaultResourceSelect
              key={field}
              label={t(`org.defaultsSection.fields.${label}`)}
              value={defaults[field]}
              options={options}
              disabled={!canEdit || saving}
              onChange={(event) => handleChange(field, event.target.value)}
              noneLabel={t('org.defaultsSection.values.noneManualSelection')}
              unavailableLabel={canViewResource
                ? t('org.defaultsSection.values.unavailable', { defaultValue: 'Unavailable resource' })
                : t('org.defaultsSection.values.detailsUnavailable', { defaultValue: 'Resource details unavailable' })}
            />
          ))}

          {canEdit && (
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 1 }}>
              <Button
                variant="contained"
                startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
                onClick={handleSave}
                disabled={saving || hasUnavailableChange || !hasChanges}
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
