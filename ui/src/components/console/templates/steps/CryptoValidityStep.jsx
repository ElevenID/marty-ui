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

const CryptoValidityStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;

  const { data: revocationProfilesData, error: revocationProfilesError } = useAsyncData(
    () => {
      if (!organizationId) {
        throw new Error('Select an organization before loading revocation profiles.');
      }
      return listRevocationProfiles({ organization_id: organizationId });
    },
    [organizationId],
  );
  const revocationProfiles = Array.isArray(revocationProfilesData) ? revocationProfilesData : [];
  const activeRevocationProfiles = revocationProfiles.filter(
    (profile) => String(profile?.status || '').trim().toUpperCase() === 'ACTIVE',
  );
  
  const validity = data.validity_rules || {
    ttl_seconds: 31536000,
    not_before_offset: 0,
    max_validity_seconds: 63072000,
  };

  const handleValidityChange = (key, value) => {
    onChange({
      validity_rules: {
        ...validity,
        [key]: parseInt(value, 10) || 0,
      },
    });
  };

  // Helper to convert seconds to days
  const secondsToDays = (seconds) => Math.floor(seconds / 86400);
  const daysToSeconds = (days) => days * 86400;

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <VpnKeyIcon />
        {t('wizards.credentialTemplate.cryptoValidityStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
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
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('wizards.credentialTemplate.cryptoValidityStep.validity.description')}
      </Typography>
      <Grid container spacing={3}>
        {/* TTL (Time to Live) */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            type="number"
            label={t('wizards.credentialTemplate.cryptoValidityStep.validity.defaultValidity')}
            value={secondsToDays(validity.ttl_seconds)}
            onChange={(e) => handleValidityChange('ttl_seconds', daysToSeconds(parseInt(e.target.value, 10)))}
            helperText={t('wizards.credentialTemplate.cryptoValidityStep.validity.defaultValidityHelper')}
            slotProps={{
              htmlInput: { min: 1 }
            }}
          />
        </Grid>

        {/* Max Validity */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            type="number"
            label={t('wizards.credentialTemplate.cryptoValidityStep.validity.maxValidity')}
            value={secondsToDays(validity.max_validity_seconds)}
            onChange={(e) => handleValidityChange('max_validity_seconds', daysToSeconds(parseInt(e.target.value, 10)))}
            helperText={t('wizards.credentialTemplate.cryptoValidityStep.validity.maxValidityHelper')}
            slotProps={{
              htmlInput: { min: 1 }
            }}
          />
        </Grid>

        {/* Not Before Offset */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            type="number"
            label={t('wizards.credentialTemplate.cryptoValidityStep.validity.notBeforeOffset')}
            value={validity.not_before_offset}
            onChange={(e) => handleValidityChange('not_before_offset', e.target.value)}
            helperText={t('wizards.credentialTemplate.cryptoValidityStep.validity.notBeforeOffsetHelper')}
            slotProps={{
              htmlInput: { min: 0 }
            }}
          />
        </Grid>
      </Grid>
      <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          <strong>{t('wizards.credentialTemplate.cryptoValidityStep.validity.example')}</strong>{' '}
          {t('wizards.credentialTemplate.cryptoValidityStep.validity.exampleDescription', {
            days: secondsToDays(validity.ttl_seconds),
            date: new Date(Date.now() + validity.ttl_seconds * 1000).toLocaleDateString(),
          })}
        </Typography>
      </Box>
      <FormControl fullWidth required error={!data.revocation_profile_id} sx={{ mt: 3 }}>
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
      </FormControl>
    </Box>
  );
};

export default CryptoValidityStep;
