/**
 * Trust & Compliance Step - Credential Template Wizard
 * 
 * Select the required trust, public issuer DID, and compliance profiles.
 * The step blocks when any required active dependency is unavailable.
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
import { useNavigate } from 'react-router';
import SecurityIcon from '@mui/icons-material/Security';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutlined';
import LanguageIcon from '@mui/icons-material/Language';
import { useTranslation } from 'react-i18next';

import { listTrustProfiles } from '../../../../services/presentationPolicyApi';
import { listComplianceProfiles } from '../../../../services/complianceProfilesApi';
import signingKeysApi from '../../../../services/signingKeysApi';
import { useConsole } from '../../../../contexts/ConsoleContext';

const firstNonEmpty = (...values) => values
  .map((value) => (typeof value === 'string' ? value.trim() : value))
  .find((value) => value);

const isActiveIssuerIdentity = (identity) => {
  if (!identity) {
    return false;
  }
  const issuerDid = firstNonEmpty(identity.issuer_did);
  return (
    String(identity.status || '').toLowerCase() === 'active' &&
    typeof issuerDid === 'string' &&
    issuerDid.startsWith('did:')
  );
};

const buildIssuerIdentityPatch = (identity) => {
  if (!identity) {
    return {
      issuer_did: null,
    };
  }

  return {
    issuer_did: firstNonEmpty(identity.issuer_did) || null,
  };
};

const TrustComplianceStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const { data: trustProfilesData = [], loading, error, reload } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading trust profiles.');
      }
      const response = await listTrustProfiles({ organization_id: activeOrgId });
      const profiles = response.data || response || [];
      return profiles.filter((p) => p.status === 'active');
    },
    [activeOrgId]
  );

  const {
    data: issuerIdentitiesData = [],
    loading: issuerIdentitiesLoading,
    error: issuerIdentitiesError,
    reload: reloadIssuerIdentities,
  } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading issuer identities.');
      }
      const response = await signingKeysApi.listPublicIssuerIdentities({
        organization_id: activeOrgId,
      });
      const identities = response?.identities || [];
      return identities.filter(isActiveIssuerIdentity);
    },
    [activeOrgId]
  );

  const {
    data: complianceProfilesData = [],
    loading: complianceProfilesLoading,
    error: complianceProfilesError,
    reload: reloadComplianceProfiles,
  } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading compliance profiles.');
      }
      const response = await listComplianceProfiles({ organization_id: activeOrgId });
      const profiles = response?.data || response || [];
      return profiles.filter((p) => (
        p.discoverable !== false
        && (p.is_system === true || String(p.status || '').toLowerCase() === 'active')
      ));
    },
    [activeOrgId]
  );

  const trustProfiles = Array.isArray(trustProfilesData) ? trustProfilesData : [];
  const activeIssuerIdentities = Array.isArray(issuerIdentitiesData)
    ? issuerIdentitiesData.filter(isActiveIssuerIdentity)
    : [];
  const issuerIdentities = [...new Map(
    activeIssuerIdentities.map((identity) => [
      firstNonEmpty(identity.issuer_did),
      identity,
    ])
  ).values()];
  const complianceProfiles = Array.isArray(complianceProfilesData) ? complianceProfilesData : [];

  // Auto-select if only one active profile and none already selected
  useEffect(() => {
    if (trustProfiles.length === 1 && !data.trust_profile_id) {
      onChange({ trust_profile_id: trustProfiles[0].id });
    }
  }, [trustProfiles]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (issuerIdentities.length === 1 && !data.issuer_did) {
      onChange(buildIssuerIdentityPatch(issuerIdentities[0]));
    }
  }, [issuerIdentities]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (complianceProfiles.length === 1 && !data.compliance_profile_id) {
      onChange({ compliance_profile_id: complianceProfiles[0].id });
    }
  }, [complianceProfiles]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleGoToTrustProfiles = () => {
    navigate('/console/org/trust/profiles/new');
  };

  const handleGoToIssuerProfiles = () => {
    navigate('/console/org/deploy/issuer-identity/new');
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ py: 4 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || t('wizards.credentialTemplate.trustComplianceStep.errors.failedToLoadTrustProfiles')}
        </Alert>
        <Button
          variant="outlined"
          onClick={reload}
        >
          {t('wizards.credentialTemplate.trustComplianceStep.blocked.refreshButton')}
        </Button>
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

  if (issuerIdentitiesLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (issuerIdentitiesError) {
    return (
      <Box sx={{ py: 4 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {issuerIdentitiesError?.message || 'Issuer identities could not be loaded.'}
        </Alert>
        <Button variant="outlined" onClick={reloadIssuerIdentities}>
          {t('wizards.credentialTemplate.trustComplianceStep.blocked.refreshButton')}
        </Button>
      </Box>
    );
  }

  if (issuerIdentities.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <LanguageIcon sx={{ fontSize: 80, color: 'warning.main', mb: 3 }} />
        <Typography variant="h5" gutterBottom>
          Active issuer DID required
        </Typography>
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 640, mx: 'auto' }}>
          Credential templates must reference an active issuer DID. The organization registry resolves its managed custody profile.
        </Typography>
        <Alert severity="warning" sx={{ maxWidth: 640, mx: 'auto', mb: 3 }}>
          Create an issuer identity first, then return to select its public DID.
        </Alert>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button variant="contained" startIcon={<AddCircleOutlineIcon />} onClick={handleGoToIssuerProfiles}>
            Create issuer identity
          </Button>
          <Button variant="outlined" onClick={reloadIssuerIdentities}>
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

      {/* Trust Profile Selection */}
      <FormControl fullWidth required sx={{ mb: 3 }}>
        <InputLabel>{t('wizards.credentialTemplate.trustComplianceStep.trustProfile.label')}</InputLabel>
        <Select
          value={data.trust_profile_id || ''}
          onChange={(e) => onChange({ trust_profile_id: e.target.value })}
          label={t('wizards.credentialTemplate.trustComplianceStep.trustProfile.label')}
          SelectDisplayProps={{ 'data-testid': 'template-trust-profile-select' }}
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

      {/* Issuer DID Selection */}
      <FormControl fullWidth required sx={{ mb: 3 }}>
        <InputLabel>Issuer DID</InputLabel>
        <Select
          value={data.issuer_did || ''}
          onChange={(e) => {
            const selectedIdentity = issuerIdentities.find(
              (identity) => firstNonEmpty(identity.issuer_did) === e.target.value
            );
            onChange(buildIssuerIdentityPatch(selectedIdentity));
          }}
          label="Issuer DID"
          disabled={issuerIdentitiesLoading}
          SelectDisplayProps={{ 'data-testid': 'template-issuer-profile-select' }}
        >
          {issuerIdentities.map((identity) => (
            <MenuItem
              key={firstNonEmpty(identity.issuer_did)}
              value={firstNonEmpty(identity.issuer_did)}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                <span>{identity.issuer_did}</span>
                <Chip
                  label={identity.issuer_did?.split(':').slice(0, 3).join(':')}
                  size="small"
                  sx={{ ml: 'auto', fontFamily: 'monospace', fontSize: '0.75rem' }}
                />
              </Box>
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {`${issuerIdentities.length} active issuer DID${issuerIdentities.length !== 1 ? 's' : ''} available. The organization registry selects its custody profile.`}
        </FormHelperText>
      </FormControl>

      {/* Show selected issuer DID */}
      {data.issuer_did && (
        <Box sx={{ mb: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
          <Typography variant="caption" color="text.secondary" gutterBottom display="block">
            Selected issuer identity
          </Typography>
          <Chip
            label={data.issuer_did}
            color="primary"
            icon={<LanguageIcon />}
          />
          <Typography variant="body2" fontFamily="monospace" color="text.secondary" sx={{ mt: 0.5 }}>
            {data.issuer_did}
          </Typography>
        </Box>
      )}

      {/* Compliance Profile Selection */}
      {complianceProfilesError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {complianceProfilesError?.message || 'Compliance profiles could not be loaded.'}
          <Button color="inherit" size="small" onClick={reloadComplianceProfiles} sx={{ ml: 2 }}>
            Retry
          </Button>
        </Alert>
      )}
      <FormControl fullWidth required sx={{ mb: 2 }}>
        <InputLabel id="credential-template-compliance-profile-label">{t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.label')}</InputLabel>
        <Select
          labelId="credential-template-compliance-profile-label"
          id="credential-template-compliance-profile"
          data-testid="template-compliance-profile-select"
          value={data.compliance_profile_id || ''}
          onChange={(e) => onChange({ compliance_profile_id: e.target.value || null })}
          label={t('wizards.credentialTemplate.trustComplianceStep.complianceProfile.label')}
          disabled={complianceProfilesLoading}
        >
          <MenuItem value="" disabled>Select an active Compliance Profile</MenuItem>
          {complianceProfilesLoading && (
            <MenuItem value="" disabled>
              Loading compliance profiles...
            </MenuItem>
          )}
          {complianceProfiles.map((profile) => (
            <MenuItem key={profile.id} value={profile.id}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                <span>{profile.name || profile.compliance_code || profile.id}</span>
                {profile.compliance_code && (
                  <Chip label={profile.compliance_code} size="small" sx={{ ml: 'auto' }} />
                )}
              </Box>
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {complianceProfiles.length > 0
            ? `${complianceProfiles.length} active compliance profile${complianceProfiles.length !== 1 ? 's' : ''} available.`
            : 'Activate a Compliance Profile before creating a Credential Template.'}
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
