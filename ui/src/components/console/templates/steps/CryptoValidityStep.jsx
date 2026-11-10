/**
 * Crypto & Validity Step - Credential Template Wizard
 * 
 * Configure validity periods and revocation settings.
 * Signing capabilities are resolved from the selected issuer DID.
 * This step is optional with sensible defaults.
 */

import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  FormHelperText,
  Alert,
  Grid,
  Button,
} from '@mui/material';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import { useTranslation } from 'react-i18next';

import { useAsyncData } from '../../../../hooks/useAsyncData';
import { useConsole } from '../../../../contexts/ConsoleContext';
import { listRevocationProfiles } from '../../../../services/presentationPolicyApi';
import { loadScopedCatalog } from '../../../../services/loadScopedCatalog';
import {
  credentialTemplateValidity, MAX_VALIDITY_DAYS, MIN_VALIDITY_OFFSET, MAX_VALIDITY_OFFSET, SECONDS_PER_DAY,
} from '../credentialTemplateValidity';

const CryptoValidityStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;
  const needsRevocation = data._issuer_selection?.requirements?.revocation_profile !== false;

  const { data: revocationProfilesData, error: revocationProfilesError } = useAsyncData(
    () => {
      if (!organizationId) {
        throw new Error('Select an organization before loading revocation profiles.');
      }
      return loadScopedCatalog(listRevocationProfiles, organizationId);
    },
    [organizationId],
  );
  const revocationProfiles = Array.isArray(revocationProfilesData) ? revocationProfilesData : [];
  const activeRevocationProfiles = revocationProfiles.filter(
    (profile) => String(profile?.status || '').trim().toUpperCase() === 'ACTIVE',
  );
  
  const validity = data.validity_rules || {};
  const { values, errors } = credentialTemplateValidity(validity);

  const handleValidityChange = (key, value) => {
    // Store the input draft, including an empty value, until submission validates it.
    const { ttl_seconds: _ttl, max_validity_seconds: _maximum, not_before_offset: _offset, ...preserved } = validity;
    onChange({
      validity_rules: {
        ...preserved,
        ...values,
        [key]: value,
      },
    });
  };

  const daysError = t('wizards.credentialTemplate.cryptoValidityStep.validation.daysRange', {
    defaultValue: 'Enter a whole number of days from 1 to {{max}}.', max: MAX_VALIDITY_DAYS,
  });
  const offsetError = t('wizards.credentialTemplate.cryptoValidityStep.validation.offsetRange', {
    defaultValue: 'Enter a whole number of seconds from {{min}} to {{max}}.', min: MIN_VALIDITY_OFFSET, max: MAX_VALIDITY_OFFSET,
  });
  const exampleExpiry = new Date(Date.now() + Number(values.default_validity_days) * SECONDS_PER_DAY * 1000);

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <VpnKeyIcon />
        {t('wizards.credentialTemplate.cryptoValidityStep.title')}
      </Typography>
      <Typography color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
        {t('wizards.credentialTemplate.cryptoValidityStep.description')}
      </Typography>
      {revocationProfilesError && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {revocationProfilesError?.message || t(
            'wizards.credentialTemplate.cryptoValidityStep.revocationProfile.loadError',
            { defaultValue: 'Revocation profiles could not be loaded. Retry before treating revocation as unavailable.' },
          )}
        </Alert>
      )}
      <Alert severity="success" sx={{ mb: 3 }}>
        <Typography variant="body2" gutterBottom>
          <strong>{t('wizards.credentialTemplate.cryptoValidityStep.defaults.title')}</strong>
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {t('wizards.credentialTemplate.cryptoValidityStep.defaults.description')}
        </Typography>
      </Alert>
      {/* Validity Period Configuration */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.credentialTemplate.cryptoValidityStep.validity.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
        {t('wizards.credentialTemplate.cryptoValidityStep.validity.description')}
      </Typography>
      <Alert severity="info" sx={{ mb: 2 }}>Validity and maximum lifetime are stored in whole days. Seconds-based durations round up to the next day; the not-before offset stays in seconds.</Alert>
      <Grid container spacing={3}>
        {/* TTL (Time to Live) */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TextField
            fullWidth
            type="number"
            required
            label={t('wizards.credentialTemplate.cryptoValidityStep.validity.defaultValidity')}
            value={values.default_validity_days}
            onChange={(e) => handleValidityChange('default_validity_days', e.target.value)}
            error={errors.default_validity_days}
            helperText={errors.default_validity_days ? daysError : t('wizards.credentialTemplate.cryptoValidityStep.validity.defaultValidityHelper')}
            slotProps={{
              htmlInput: { min: 1, max: MAX_VALIDITY_DAYS, step: 1 }
            }}
          />
        </Grid>

        {/* Max Validity */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TextField
            fullWidth
            type="number"
            required
            label={t('wizards.credentialTemplate.cryptoValidityStep.validity.maxValidity')}
            value={values.max_validity_days}
            onChange={(e) => handleValidityChange('max_validity_days', e.target.value)}
            error={errors.max_validity_days}
            helperText={errors.max_validity_days ? daysError : t('wizards.credentialTemplate.cryptoValidityStep.validity.maxValidityHelper')}
            slotProps={{
              htmlInput: { min: 1, max: MAX_VALIDITY_DAYS, step: 1 }
            }}
          />
        </Grid>

        {/* Not Before Offset */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TextField
            fullWidth
            type="number"
            required
            label={t('wizards.credentialTemplate.cryptoValidityStep.validity.notBeforeOffset')}
            value={values.not_before_offset_seconds}
            onChange={(e) => handleValidityChange('not_before_offset_seconds', e.target.value)}
            error={errors.not_before_offset_seconds}
            helperText={errors.not_before_offset_seconds ? offsetError : t('wizards.credentialTemplate.cryptoValidityStep.validity.notBeforeOffsetHelper')}
            slotProps={{
              htmlInput: { min: MIN_VALIDITY_OFFSET, max: MAX_VALIDITY_OFFSET, step: 1 }
            }}
          />
        </Grid>
      </Grid>
      {!errors.default_validity_days && Number.isFinite(exampleExpiry.getTime()) && <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          <strong>{t('wizards.credentialTemplate.cryptoValidityStep.validity.example')}</strong>{' '}
          {t('wizards.credentialTemplate.cryptoValidityStep.validity.exampleDescription', {
            days: values.default_validity_days,
            date: exampleExpiry.toLocaleDateString(),
          })}
        </Typography>
      </Box>}
      {!needsRevocation && <Alert severity="info" sx={{ mt: 3 }}>This issuance protocol does not use a digital Revocation Profile.</Alert>}
      {needsRevocation && <FormControl fullWidth required error={!data.revocation_profile_id} sx={{ mt: 3 }}>
        <InputLabel id="credential-template-revocation-profile-label">
          {t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.label')}
        </InputLabel>
        <Select
          id="credential-template-revocation-profile"
          labelId="credential-template-revocation-profile-label"
          value={data.revocation_profile_id || ''}
          onChange={(e) => onChange({ revocation_profile_id: e.target.value || null })}
          label={t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.label')}
        >
          <MenuItem value="" disabled>
            <em>Select an active Revocation Profile</em>
          </MenuItem>
          {activeRevocationProfiles.map((profile) => (
            <MenuItem key={profile.id} value={profile.id}>
              {profile.name}
              {profile.check_mode ? ` (${profile.check_mode.replace('_', ' ')})` : ''}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {data.revocation_profile_id
            ? t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.helper')
            : 'An active Revocation Profile is required before this template can be activated.'}
        </FormHelperText>
        {activeRevocationProfiles.length === 0 && !revocationProfilesError && (
          <Button
            href="/console/org/trust/revocation/new"
            size="small"
            sx={{ alignSelf: 'flex-start', mt: 1 }}
          >
            Create Revocation Profile
          </Button>
        )}
      </FormControl>}
    </Box>
  );
};

export default CryptoValidityStep;
