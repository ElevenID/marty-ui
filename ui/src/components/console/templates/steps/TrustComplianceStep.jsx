/**
 * Trust & Compliance Step - Credential Template Wizard
 * 
 * Select the trust profile and optional compliance profile.
 * Trust Profile is required; blocks if none active.
 */

import { useEffect } from 'react';
import { useAsyncData } from '../../../../hooks/useAsyncData';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Alert,
  CircularProgress,
  Button,
  Chip,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import SecurityIcon from '@mui/icons-material/Security';
import WarningIcon from '@mui/icons-material/Warning';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import LanguageIcon from '@mui/icons-material/Language';
import { useTranslation } from 'react-i18next';

import { listTrustProfiles } from '../../../../services/presentationPolicyApi';
import signingKeysApi from '../../../../services/signingKeysApi';

const TrustComplianceStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { data: trustProfiles = [], loading, error } = useAsyncData(
    async () => {
      const response = await listTrustProfiles();
      const profiles = response.data || response || [];
      return profiles.filter((p) => p.status === 'active');
    },
    []
  );

  const { data: issuerProfiles = [], loading: issuerProfilesLoading } = useAsyncData(
    async () => {
      const response = await signingKeysApi.listIssuerProfiles();
      const profiles = response?.profiles || [];
      return profiles.filter((p) => p.status === 'active');
    },
    []
  );

  // Auto-select if only one active profile and none already selected
  useEffect(() => {
    if (trustProfiles.length === 1 && !data.trust_profile_id) {
      onChange({ trust_profile_id: trustProfiles[0].id });
    }
  }, [trustProfiles]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleGoToTrustProfiles = () => {
    navigate('/console/org/trust/profiles/new');
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  // No active trust profiles - block progression
  if (trustProfiles.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <SecurityIcon sx={{ fontSize: 80, color: 'warning.main', mb: 3 }} />
        
        <Typography variant="h5" gutterBottom>
          {t('wizards.credentialTemplate.trustComplianceStep.blocked.title')}
        </Typography>
        
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 600, mx: 'auto' }}>
          {t('wizards.credentialTemplate.trustComplianceStep.blocked.description')}
        </Typography>

        <Alert severity="warning" sx={{ maxWidth: 600, mx: 'auto', mb: 3 }}>
          <Typography variant="body2">
            {t('wizards.credentialTemplate.trustComplianceStep.blocked.alert')}
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button
            variant="contained"
            startIcon={<AddCircleOutlineIcon />}
            onClick={handleGoToTrustProfiles}
          >
            {t('wizards.credentialTemplate.trustComplianceStep.blocked.createButton')}
          </Button>
          <Button
            variant="outlined"
            onClick={() => window.location.reload()}
          >
            {t('wizards.credentialTemplate.trustComplianceStep.blocked.refreshButton')}
          </Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <SecurityIcon />
        {t('wizards.credentialTemplate.trustComplianceStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.credentialTemplate.trustComplianceStep.description')}
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || t('wizards.credentialTemplate.trustComplianceStep.errors.failedToLoadTrustProfiles')}
        </Alert>
      )}

      {/* Trust Profile Selection */}
      <FormControl fullWidth required sx={{ mb: 3 }}>
        <InputLabel>{t('wizards.credentialTemplate.trustComplianceStep.trustProfile.label')}</InputLabel>
        <Select
          value={data.trust_profile_id || ''}
          onChange={(e) => onChange({ trust_profile_id: e.target.value })}
          label={t('wizards.credentialTemplate.trustComplianceStep.trustProfile.label')}
        >
          {trustProfiles.map((profile) => (
            <MenuItem key={profile.id} value={profile.id}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                <span>{profile.name}</span>
                {profile.framework_type && (
                  <Chip
                    label={profile.framework_type.toUpperCase()}
                    size="small"
                    sx={{ ml: 'auto' }}
                  />
                )}
              </Box>
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {t('wizards.credentialTemplate.trustComplianceStep.trustProfile.helper', {
            count: trustProfiles.length,
          })}
        </FormHelperText>
      </FormControl>

      {/* Show selected trust profile */}
      {data.trust_profile_id && (
        <Box sx={{ mb: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
          <Typography variant="caption" color="text.secondary" gutterBottom display="block">
            {t('wizards.credentialTemplate.trustComplianceStep.trustProfile.selectedTitle')}
          </Typography>
          <Chip
            label={trustProfiles.find((p) => p.id === data.trust_profile_id)?.name || t('wizards.credentialTemplate.trustComplianceStep.trustProfile.unknown')}
            color="primary"
            icon={<SecurityIcon />}
          />
        </Box>
      )}

      {/* Issuer Profile Selection (Optional) */}
      <FormControl fullWidth sx={{ mb: 3 }}>
        <InputLabel>Issuer Profile</InputLabel>
        <Select
          value={data.issuer_profile_id || ''}
          onChange={(e) => onChange({ issuer_profile_id: e.target.value || null })}
          label="Issuer Profile"
          disabled={issuerProfilesLoading}
        >
          <MenuItem value="">
            <em>Default (org signing key)</em>
          </MenuItem>
          {issuerProfiles.map((profile) => (
            <MenuItem key={profile.id} value={profile.id}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                <span>{profile.name || profile.issuer_did}</span>
                <Chip
                  label={profile.issuer_did?.split(':').slice(0, 3).join(':')}
                  size="small"
                  sx={{ ml: 'auto', fontFamily: 'monospace', fontSize: '0.75rem' }}
                />
              </Box>
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {issuerProfiles.length > 0
            ? `${issuerProfiles.length} active issuer profile${issuerProfiles.length !== 1 ? 's' : ''} available. Credentials will claim this DID as the issuer.`
            : 'No active issuer profiles. Credentials will use the default org signing key.'}
        </FormHelperText>
      </FormControl>

      {/* Show selected issuer profile */}
      {data.issuer_profile_id && (
        <Box sx={{ mb: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
          <Typography variant="caption" color="text.secondary" gutterBottom display="block">
            Selected issuer identity
          </Typography>
          <Chip
            label={issuerProfiles.find((p) => p.id === data.issuer_profile_id)?.name || 'Unknown profile'}
            color="primary"
            icon={<LanguageIcon />}
          />
          <Typography variant="body2" fontFamily="monospace" color="text.secondary" sx={{ mt: 0.5 }}>
            {issuerProfiles.find((p) => p.id === data.issuer_profile_id)?.issuer_did || ''}
          </Typography>
        </Box>
      )}

      {/* Compliance Profile Selection (Optional) */}
      <FormControl fullWidth sx={{ mb: 2 }}>
        <InputLabel>{t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.label')}</InputLabel>
        <Select
          value={data.compliance_profile_id || ''}
          onChange={(e) => onChange({ compliance_profile_id: e.target.value || null })}
          label={t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.label')}
        >
          <MenuItem value="">
            <em>{t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.noneOption')}</em>
          </MenuItem>
          {/* TODO: Load actual compliance profiles when available */}
          <MenuItem value="gdpr" disabled>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.gdpr')}
              <Chip label={t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.comingSoon')} size="small" />
            </Box>
          </MenuItem>
        </Select>
        <FormHelperText>
          {t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.helper')}
        </FormHelperText>
      </FormControl>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2" gutterBottom>
          <strong>{t('wizards.credentialTemplate.trustComplianceStep.guidance.title')}</strong>
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {t('wizards.credentialTemplate.trustComplianceStep.guidance.description')}
        </Typography>
      </Alert>

      <Alert severity="info" icon={<SecurityIcon />}>
        <Typography variant="body2">
          {t('wizards.credentialTemplate.trustComplianceStep.guidance.securityDescription')}
        </Typography>
      </Alert>
    </Box>
  );
};

export default TrustComplianceStep;
