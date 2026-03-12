/**
 * Claims Configuration Step
 * 
 * Configure policy name, purpose, credential types, and required claims.
 * Integrates with CredentialTemplate API for claim name autocomplete.
 */

import { useAsyncData } from '../../../../hooks/useAsyncData';
import {
  Box,
  Typography,
  TextField,
  Button,
  IconButton,
  Card,
  CardContent,
  Chip,
  Autocomplete,
  FormControlLabel,
  Switch,
  Alert,
  Divider,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { useTranslation } from 'react-i18next';

import { listCredentialTemplates } from '../../../../services/presentationPolicyApi';

const ClaimsConfigurationStep = ({ policyConfig, onConfigChange }) => {
  const { t } = useTranslation('console');
  const { data: { templates: credentialTemplates = [], claims: availableClaims = [] } = {} } = useAsyncData(
    async () => {
      const response = await listCredentialTemplates();
      const templates = response.data || response || [];
      const claims = templates.flatMap(template =>
        (template.claims || []).map(claim => ({
          name: claim.name,
          display_name: claim.display_name || claim.name,
          credential_type: template.credential_type,
          data_type: claim.data_type,
          predicate_type: claim.predicate_type,
        }))
      );
      return { templates, claims };
    },
    []
  );

  const handleFieldChange = (field, value) => {
    onConfigChange({
      ...policyConfig,
      [field]: value,
    });
  };

  const handleAddClaim = () => {
    const newClaim = {
      claim_name: '',
      credential_type: policyConfig.accepted_credential_types[0] || '',
      accept_predicate: true,
      required_value: null,
    };

    onConfigChange({
      ...policyConfig,
      required_claims: [...policyConfig.required_claims, newClaim],
    });
  };

  const handleRemoveClaim = (index) => {
    const updatedClaims = policyConfig.required_claims.filter((_, i) => i !== index);
    onConfigChange({
      ...policyConfig,
      required_claims: updatedClaims,
    });
  };

  const handleClaimChange = (index, field, value) => {
    const updatedClaims = [...policyConfig.required_claims];
    updatedClaims[index] = {
      ...updatedClaims[index],
      [field]: value,
    };
    onConfigChange({
      ...policyConfig,
      required_claims: updatedClaims,
    });
  };

  const handleAddCredentialType = (newType) => {
    if (newType && !policyConfig.accepted_credential_types.includes(newType)) {
      onConfigChange({
        ...policyConfig,
        accepted_credential_types: [...policyConfig.accepted_credential_types, newType],
      });
    }
  };

  const handleRemoveCredentialType = (typeToRemove) => {
    onConfigChange({
      ...policyConfig,
      accepted_credential_types: policyConfig.accepted_credential_types.filter(t => t !== typeToRemove),
    });
  };

  // Get available credential types from templates
  const availableCredentialTypes = credentialTemplates.map(t => t.credential_type).filter(Boolean);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.presentationPolicy.claimsConfigurationStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.presentationPolicy.claimsConfigurationStep.description')}
      </Typography>

      {/* Basic Information */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.claimsConfigurationStep.sections.basicInfo')}
          </Typography>

          <TextField
            fullWidth
            label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.policyName')}
            value={policyConfig.name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            required
            sx={{ mb: 2 }}
            helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.policyName')}
          />

          <TextField
            fullWidth
            label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.description')}
            value={policyConfig.description}
            onChange={(e) => handleFieldChange('description', e.target.value)}
            multiline
            rows={2}
            sx={{ mb: 2 }}
            helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.description')}
          />

          <TextField
            fullWidth
            label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.purposeStatement')}
            value={policyConfig.purpose}
            onChange={(e) => handleFieldChange('purpose', e.target.value)}
            required
            multiline
            rows={2}
            helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.purposeStatement')}
          />
        </CardContent>
      </Card>

      {/* Accepted Credential Types */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.claimsConfigurationStep.sections.acceptedCredentialTypes')}
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            {t('wizards.presentationPolicy.claimsConfigurationStep.helpers.credentialTypesQuestion')}
          </Typography>

          <Autocomplete
            freeSolo
            options={availableCredentialTypes}
            value=""
            onChange={(e, newValue) => handleAddCredentialType(newValue)}
            renderInput={(params) => (
              <TextField
                {...params}
                label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.addCredentialType')}
                placeholder={t('wizards.presentationPolicy.claimsConfigurationStep.placeholders.credentialType')}
                helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.addCredentialType')}
              />
            )}
            sx={{ mb: 2 }}
          />

          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {policyConfig.accepted_credential_types.map((type) => (
              <Chip
                key={type}
                label={type}
                onDelete={() => handleRemoveCredentialType(type)}
                color="primary"
              />
            ))}
          </Box>

          {policyConfig.accepted_credential_types.length === 0 && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              {t('wizards.presentationPolicy.claimsConfigurationStep.alerts.addCredentialTypeFirst')}
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Required Claims */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              {t('wizards.presentationPolicy.claimsConfigurationStep.sections.requiredClaims')}
            </Typography>
            <Button
              startIcon={<AddIcon />}
              onClick={handleAddClaim}
              disabled={policyConfig.accepted_credential_types.length === 0}
            >
              {t('wizards.presentationPolicy.claimsConfigurationStep.quickActions.addClaim')}
            </Button>
          </Box>

          {policyConfig.accepted_credential_types.length === 0 && (
            <Alert severity="info">
              {t('wizards.presentationPolicy.claimsConfigurationStep.alerts.addTypesBeforeClaims')}
            </Alert>
          )}

          {policyConfig.required_claims.length === 0 && policyConfig.accepted_credential_types.length > 0 && (
            <Alert severity="warning">
              {t('wizards.presentationPolicy.claimsConfigurationStep.alerts.addClaim')}
            </Alert>
          )}

          {policyConfig.required_claims.map((claim, index) => (
            <Card key={index} variant="outlined" sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                  <Typography variant="subtitle2" color="primary">
                    {t('wizards.presentationPolicy.claimsConfigurationStep.labels.claim', { index: index + 1 })}
                  </Typography>
                  <IconButton
                    size="small"
                    onClick={() => handleRemoveClaim(index)}
                    color="error"
                  >
                    <DeleteIcon />
                  </IconButton>
                </Box>

                <Autocomplete
                  freeSolo
                  options={availableClaims
                    .filter(c => policyConfig.accepted_credential_types.includes(c.credential_type))
                    .map(c => c.name)
                  }
                  value={claim.claim_name}
                  onChange={(e, newValue) => handleClaimChange(index, 'claim_name', newValue || '')}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.claimName')}
                      required
                      helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.claimName')}
                      onChange={(e) => handleClaimChange(index, 'claim_name', e.target.value)}
                    />
                  )}
                  sx={{ mb: 2 }}
                />

                <Autocomplete
                  options={policyConfig.accepted_credential_types}
                  value={claim.credential_type}
                  onChange={(e, newValue) => handleClaimChange(index, 'credential_type', newValue || '')}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.fromCredentialType')}
                      required
                      helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.fromCredentialType')}
                    />
                  )}
                  sx={{ mb: 2 }}
                />

                <FormControlLabel
                  control={
                    <Switch
                      checked={claim.accept_predicate}
                      onChange={(e) => handleClaimChange(index, 'accept_predicate', e.target.checked)}
                    />
                  }
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Typography variant="body2">{t('wizards.presentationPolicy.claimsConfigurationStep.labels.acceptPredicateProof')}</Typography>
                      <IconButton size="small" sx={{ ml: 0.5 }}>
                        <InfoOutlinedIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  }
                />
                
                {claim.accept_predicate && (
                  <Alert severity="info" icon={<InfoOutlinedIcon />} sx={{ mt: 1 }}>
                    <Typography variant="caption">
                      {t('wizards.presentationPolicy.claimsConfigurationStep.alerts.predicateInfo')}
                    </Typography>
                  </Alert>
                )}

                <Divider sx={{ my: 2 }} />

                <TextField
                  fullWidth
                  label={t('wizards.presentationPolicy.claimsConfigurationStep.fields.requiredValue')}
                  value={claim.required_value || ''}
                  onChange={(e) => handleClaimChange(index, 'required_value', e.target.value || null)}
                  helperText={t('wizards.presentationPolicy.claimsConfigurationStep.helpers.requiredValue')}
                  size="small"
                />
              </CardContent>
            </Card>
          ))}
        </CardContent>
      </Card>

      {/* Global Preferences */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.claimsConfigurationStep.sections.presentationOptions')}
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={policyConfig.prefer_predicates}
                onChange={(e) => handleFieldChange('prefer_predicates', e.target.checked)}
              />
            }
            label={t('wizards.presentationPolicy.claimsConfigurationStep.labels.preferPredicateProofs')}
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4, mb: 2 }}>
            {t('wizards.presentationPolicy.claimsConfigurationStep.captions.preferPredicates')}
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={policyConfig.single_presentation}
                onChange={(e) => handleFieldChange('single_presentation', e.target.checked)}
              />
            }
            label={t('wizards.presentationPolicy.claimsConfigurationStep.labels.singlePresentation')}
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            {t('wizards.presentationPolicy.claimsConfigurationStep.captions.singlePresentation')}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ClaimsConfigurationStep;
