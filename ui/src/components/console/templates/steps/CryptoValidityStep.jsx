/**
 * Crypto & Validity Step - Credential Template Wizard
 * 
 * Configure signing algorithm, validity periods, and revocation settings.
 * This step is optional with sensible defaults.
 */

import { useState } from 'react';
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
  Divider,
  Grid,
  Button,
  Collapse,
} from '@mui/material';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import InfoIcon from '@mui/icons-material/Info';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { useTranslation } from 'react-i18next';

import { useAsyncData } from '../../../../hooks/useAsyncData';
import { useAuth } from '../../../../hooks/useAuth';
import { listRevocationProfiles } from '../../../../services/presentationPolicyApi';

const getSigningAlgorithms = (t) => [
  { value: 'ES256', label: t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.labels.ES256') },
  { value: 'ES384', label: t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.labels.ES384') },
  { value: 'ES512', label: t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.labels.ES512') },
  { value: 'EdDSA', label: t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.labels.EdDSA') },
  { value: 'RS256', label: t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.labels.RS256') },
];

const CryptoValidityStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const [showAdvanced, setShowAdvanced] = useState(false);

  const { data: revocationProfiles = [] } = useAsyncData(
    () =>
      organizationId
        ? listRevocationProfiles({ organization_id: organizationId })
        : Promise.resolve([]),
    [organizationId],
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
            inputProps={{ min: 1 }}
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
            inputProps={{ min: 1 }}
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
            inputProps={{ min: 0 }}
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

      {/* Advanced Options Toggle */}
      <Box sx={{ mt: 3 }}>
        <Button
          fullWidth
          variant="outlined"
          onClick={() => setShowAdvanced(!showAdvanced)}
          endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          {t('wizards.credentialTemplate.cryptoValidityStep.advanced.toggle', {
            action: showAdvanced
              ? t('wizards.credentialTemplate.cryptoValidityStep.advanced.hide')
              : t('wizards.credentialTemplate.cryptoValidityStep.advanced.show'),
          })}
        </Button>

        <Collapse in={showAdvanced}>
          <Box sx={{ mt: 3 }}>
            <Divider sx={{ mb: 3 }} />

            {/* Signing Algorithm */}
            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>{t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.label')}</InputLabel>
              <Select
                value={data.signing_algorithm || 'ES256'}
                onChange={(e) => onChange({ signing_algorithm: e.target.value })}
                label={t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.label')}
              >
                {getSigningAlgorithms(t).map((alg) => (
                  <MenuItem key={alg.value} value={alg.value}>
                    {alg.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t('wizards.credentialTemplate.cryptoValidityStep.signingAlgorithm.helper')}
              </FormHelperText>
            </FormControl>

            <Divider sx={{ my: 3 }} />

            {/* Revocation Profile */}
            <FormControl fullWidth>
              <InputLabel>{t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.label')}</InputLabel>
              <Select
                value={data.revocation_profile_id || ''}
                onChange={(e) => onChange({ revocation_profile_id: e.target.value || null })}
                label={t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.label')}
              >
                <MenuItem value="">
                  <em>{t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.none')}</em>
                </MenuItem>
                {revocationProfiles.map((profile) => (
                  <MenuItem key={profile.id} value={profile.id}>
                    {profile.name}
                    {profile.check_mode ? ` (${profile.check_mode.replace('_', ' ')})` : ''}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t('wizards.credentialTemplate.cryptoValidityStep.revocationProfile.helper')}
              </FormHelperText>
            </FormControl>
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
};

export default CryptoValidityStep;
