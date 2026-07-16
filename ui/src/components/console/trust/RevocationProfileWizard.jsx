/**
 * Revocation Profile Wizard
 *
 * Single-page form for creating a new revocation profile.
 * Collects: name, check mode, revocation mechanisms, status list URL,
 * optional grace period, cache TTL, and description.
 */

import { useState, useCallback } from 'react';
import { useNavigate, Link as RouterLink } from 'react-router-dom';
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
  InputAdornment,
  InputLabel,
  Link,
  MenuItem,
  Paper,
  Select,
  TextField,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import SaveIcon from '@mui/icons-material/Save';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createRevocationProfile } from '../../../services/presentationPolicyApi';

const CHECK_MODES = [
  {
    value: 'ALWAYS',
    label: 'Always',
    description: 'Check current credential status for every verification.',
  },
  {
    value: 'CACHED',
    label: 'Cached',
    description: 'Use status results for the configured cache period.',
  },
  {
    value: 'OFFLINE_GRACE',
    label: 'Offline Grace',
    description: 'Accept a last-known status within the configured grace period.',
  },
  {
    value: 'DISABLED',
    label: 'Disabled',
    description: 'Do not perform credential status checks.',
  },
];

const MECHANISMS = [
  { value: 'STATUS_LIST_2021', label: 'Status List 2021' },
  { value: 'BITSTRING_STATUS_LIST', label: 'Bitstring Status List' },
  { value: 'OCSP', label: 'OCSP' },
  { value: 'CRL', label: 'CRL' },
];

const INITIAL_FORM = {
  name: '',
  description: '',
  check_mode: 'ALWAYS',
  revocation_mechanism: ['STATUS_LIST_2021'],
  status_list_url: '',
  offline_grace_seconds: '',
  cache_ttl_seconds: '',
};

function RevocationProfileWizard() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;

  const [form, setForm] = useState(INITIAL_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);

  const handleMechanismToggle = useCallback((mechanism) => {
    setForm((prev) => {
      const current = prev.revocation_mechanism || [];
      return {
        ...prev,
        revocation_mechanism: current.includes(mechanism)
          ? current.filter((m) => m !== mechanism)
          : [...current, mechanism],
      };
    });
  }, []);

  const handleSubmit = useCallback(async () => {
    setSubmitting(true);
    setSubmitError(null);
    try {
      const payload = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        check_mode: form.check_mode,
        revocation_mechanism: form.revocation_mechanism,
        status_list_url: form.status_list_url.trim() || null,
        organization_id: organizationId,
      };
      if (form.offline_grace_seconds !== '') {
        payload.offline_grace_seconds = Number(form.offline_grace_seconds);
      }
      if (form.cache_ttl_seconds !== '') {
        payload.cache_ttl_seconds = Number(form.cache_ttl_seconds);
      }

      const created = await createRevocationProfile(payload);
      navigate(`/console/org/trust/revocation/${created.id}`);
    } catch (err) {
      setSubmitError(
        err?.message ||
          t('trust.revocationWizard.submitFailed', 'Failed to create revocation profile.')
      );
      setSubmitting(false);
    }
  }, [form, organizationId, navigate, t]);

  const isValid = form.name.trim().length > 0
    && form.revocation_mechanism.length > 0
    && (form.check_mode !== 'CACHED' || Number(form.cache_ttl_seconds) > 0)
    && (form.check_mode !== 'OFFLINE_GRACE' || Number(form.offline_grace_seconds) > 0);

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
        <Link
          component={RouterLink}
          to="/console/org/trust/revocation"
          underline="hover"
          color="inherit"
        >
          {t('trust.breadcrumbs.revocationProfiles', 'Revocation Profiles')}
        </Link>
        <Typography color="text.primary">
          {t('trust.revocationWizard.breadcrumbNew', 'New')}
        </Typography>
      </Breadcrumbs>

      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          {t('trust.revocationWizard.title', 'New Revocation Profile')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t(
            'trust.revocationWizard.subtitle',
            'Define how revocation status is checked when verifying credentials under this profile.'
          )}
        </Typography>
      </Box>

      {submitError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {submitError}
        </Alert>
      )}

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" fontWeight={600} gutterBottom>
          {t('trust.revocationWizard.basicInfoTitle', 'Basic Information')}
        </Typography>

        {/* Name */}
        <TextField
          fullWidth
          required
          label={t('trust.revocationWizard.nameLabel', 'Profile Name')}
          value={form.name}
          onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
          sx={{ mb: 3 }}
          helperText={t('trust.revocationWizard.nameHelper', 'A descriptive name for this revocation configuration.')}
          inputProps={{ 'data-testid': 'revocationWizard.name' }}
        />

        {/* Description */}
        <TextField
          fullWidth
          multiline
          rows={2}
          label={t('trust.revocationWizard.descriptionLabel', 'Description (optional)')}
          value={form.description}
          onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
          sx={{ mb: 3 }}
          inputProps={{ 'data-testid': 'revocationWizard.description' }}
        />

        {/* Check Mode */}
        <FormControl fullWidth sx={{ mb: 3 }}>
          <InputLabel>{t('trust.revocationWizard.checkModeLabel', 'Revocation Check Mode')}</InputLabel>
          <Select
            value={form.check_mode}
            onChange={(e) => setForm((prev) => ({ ...prev, check_mode: e.target.value }))}
            label={t('trust.revocationWizard.checkModeLabel', 'Revocation Check Mode')}
            inputProps={{ 'data-testid': 'revocationWizard.checkMode' }}
          >
            {CHECK_MODES.map((mode) => (
              <MenuItem key={mode.value} value={mode.value}>
                <Box>
                  <Typography variant="body2" fontWeight={500}>
                    {mode.label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {mode.description}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
          <FormHelperText>
            {t(
              'trust.revocationWizard.checkModeHelper',
              'Determines behaviour when the revocation endpoint is unavailable.'
            )}
          </FormHelperText>
        </FormControl>

        {/* Mechanisms */}
        <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            {t('trust.revocationWizard.mechanismsLabel', 'Revocation Mechanisms')}
          </Typography>
          <FormHelperText sx={{ mt: 0, mb: 1 }}>
            {t('trust.revocationWizard.mechanismsHelper', 'Select all revocation methods this profile should support.')}
          </FormHelperText>
          <FormGroup>
            {MECHANISMS.map((m) => (
              <FormControlLabel
                key={m.value}
                control={
                  <Checkbox
                    checked={(form.revocation_mechanism || []).includes(m.value)}
                    onChange={() => handleMechanismToggle(m.value)}
                    data-testid={`revocationWizard.mechanism.${m.value}`}
                  />
                }
                label={m.label}
              />
            ))}
          </FormGroup>
          {form.revocation_mechanism.length === 0 && (
            <FormHelperText error>
              {t('trust.revocationWizard.mechanismsRequired', 'Select at least one mechanism.')}
            </FormHelperText>
          )}
        </FormControl>

        {/* Status List URL */}
        <TextField
          fullWidth
          label={t('trust.revocationWizard.statusListUrlLabel', 'Status List URL (optional)')}
          value={form.status_list_url}
          onChange={(e) => setForm((prev) => ({ ...prev, status_list_url: e.target.value }))}
          sx={{ mb: 3 }}
          placeholder="https://issuer.example.com/status/1"
          helperText={t(
            'trust.revocationWizard.statusListUrlHelper',
            'Endpoint that serves the status list credential. Required for StatusList2021 and BitstringStatusList mechanisms.'
          )}
          inputProps={{ 'data-testid': 'revocationWizard.statusListUrl', style: { fontFamily: 'monospace' } }}
        />
      </Paper>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" fontWeight={600} gutterBottom>
          {t('trust.revocationWizard.timingTitle', 'Timing Configuration')}
        </Typography>

        {form.check_mode === 'OFFLINE_GRACE' && (
          <TextField
            fullWidth
            required
            type="number"
            label={t('trust.revocationWizard.gracePeriodLabel', 'Offline Grace Period')}
            value={form.offline_grace_seconds}
            onChange={(e) => setForm((prev) => ({ ...prev, offline_grace_seconds: e.target.value }))}
            sx={{ mb: 3 }}
            InputProps={{
              endAdornment: <InputAdornment position="end">seconds</InputAdornment>,
              inputProps: { min: 1, 'data-testid': 'revocationWizard.gracePeriod' },
            }}
            helperText={t(
              'trust.revocationWizard.gracePeriodHelper',
              'How long a last-known status may be used while the live endpoint is unavailable.'
            )}
          />
        )}

        {/* Cache TTL */}
        {form.check_mode === 'CACHED' && (
          <TextField
            fullWidth
            required
            type="number"
            label={t('trust.revocationWizard.cacheTtlLabel', 'Cache TTL')}
            value={form.cache_ttl_seconds}
            onChange={(e) => setForm((prev) => ({ ...prev, cache_ttl_seconds: e.target.value }))}
            InputProps={{
              endAdornment: <InputAdornment position="end">seconds</InputAdornment>,
              inputProps: { min: 1, 'data-testid': 'revocationWizard.cacheTtl' },
            }}
            helperText={t(
              'trust.revocationWizard.cacheTtlHelper',
              'How long to reuse a status result before checking again.'
            )}
          />
        )}
      </Paper>

      {/* Actions */}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="contained"
          startIcon={submitting ? <CircularProgress size={16} color="inherit" /> : <SaveIcon />}
          onClick={handleSubmit}
          disabled={submitting || !isValid}
          data-testid="revocationWizard.submit"
        >
          {submitting
            ? t('trust.revocationWizard.creating', 'Creating...')
            : t('trust.revocationWizard.createButton', 'Create Profile')}
        </Button>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/revocation')}
          disabled={submitting}
        >
          {t('trust.revocationWizard.cancel', 'Cancel')}
        </Button>
      </Box>
    </Box>
  );
}

export default RevocationProfileWizard;
