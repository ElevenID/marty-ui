/**
 * Claims Configuration Step
 * 
 * Configure policy name, purpose, credential types, and required claims.
 * Integrates with CredentialTemplate API for claim name autocomplete.
 */

import React, { useState, useEffect } from 'react';
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
  CircularProgress,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

import { listCredentialTemplates } from '../../../../services/presentationPolicyApi';

const ClaimsConfigurationStep = ({ policyConfig, onConfigChange }) => {
  const [credentialTemplates, setCredentialTemplates] = useState([]);
  const [loadingTemplates, setLoadingTemplates] = useState(false);
  const [availableClaims, setAvailableClaims] = useState([]);

  useEffect(() => {
    fetchCredentialTemplates();
  }, []);

  const fetchCredentialTemplates = async () => {
    setLoadingTemplates(true);
    try {
      const response = await listCredentialTemplates();
      const templates = response.data || response || [];
      setCredentialTemplates(templates);
      
      // Extract all available claims from templates
      const claims = [];
      templates.forEach(template => {
        if (template.claims) {
          template.claims.forEach(claim => {
            claims.push({
              name: claim.name,
              display_name: claim.display_name || claim.name,
              credential_type: template.credential_type,
              data_type: claim.data_type,
              predicate_type: claim.predicate_type,
            });
          });
        }
      });
      setAvailableClaims(claims);
    } catch (err) {
      console.error('Failed to fetch credential templates:', err);
    } finally {
      setLoadingTemplates(false);
    }
  };

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
        Configure Claims
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Define the basic information and required claims for this presentation policy.
      </Typography>

      {/* Basic Information */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            Basic Information
          </Typography>

          <TextField
            fullWidth
            label="Policy Name"
            value={policyConfig.name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            required
            sx={{ mb: 2 }}
            helperText="A descriptive name for this policy"
          />

          <TextField
            fullWidth
            label="Description"
            value={policyConfig.description}
            onChange={(e) => handleFieldChange('description', e.target.value)}
            multiline
            rows={2}
            sx={{ mb: 2 }}
            helperText="Optional details about this policy"
          />

          <TextField
            fullWidth
            label="Purpose Statement"
            value={policyConfig.purpose}
            onChange={(e) => handleFieldChange('purpose', e.target.value)}
            required
            multiline
            rows={2}
            helperText="Explain to users why you need this information (shown during consent)"
          />
        </CardContent>
      </Card>

      {/* Accepted Credential Types */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            Accepted Credential Types
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            Which credential types can satisfy this policy?
          </Typography>

          <Autocomplete
            freeSolo
            options={availableCredentialTypes}
            value=""
            onChange={(e, newValue) => handleAddCredentialType(newValue)}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Add credential type"
                placeholder="e.g., org.iso.18013.5.1.mDL"
                helperText="Select from templates or enter custom type"
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
              Add at least one accepted credential type
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Required Claims */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              Required Claims
            </Typography>
            <Button
              startIcon={<AddIcon />}
              onClick={handleAddClaim}
              disabled={policyConfig.accepted_credential_types.length === 0}
            >
              Add Claim
            </Button>
          </Box>

          {policyConfig.accepted_credential_types.length === 0 && (
            <Alert severity="info">
              Add credential types above before configuring claims
            </Alert>
          )}

          {policyConfig.required_claims.length === 0 && policyConfig.accepted_credential_types.length > 0 && (
            <Alert severity="warning">
              Add at least one required claim
            </Alert>
          )}

          {policyConfig.required_claims.map((claim, index) => (
            <Card key={index} variant="outlined" sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                  <Typography variant="subtitle2" color="primary">
                    Claim {index + 1}
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
                      label="Claim Name"
                      required
                      helperText="The name of the claim to request"
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
                      label="From Credential Type"
                      required
                      helperText="Which credential type contains this claim"
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
                      <Typography variant="body2">Accept Predicate Proof</Typography>
                      <IconButton size="small" sx={{ ml: 0.5 }}>
                        <InfoOutlinedIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  }
                />
                
                {claim.accept_predicate && (
                  <Alert severity="info" icon={<InfoOutlinedIcon />} sx={{ mt: 1 }}>
                    <Typography variant="caption">
                      Privacy-enhanced: User can prove attributes without revealing actual values
                      (e.g., prove "age over 21" without showing birth date)
                    </Typography>
                  </Alert>
                )}

                <Divider sx={{ my: 2 }} />

                <TextField
                  fullWidth
                  label="Required Value (Optional)"
                  value={claim.required_value || ''}
                  onChange={(e) => handleClaimChange(index, 'required_value', e.target.value || null)}
                  helperText="If specified, the claim must match this exact value"
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
            Presentation Options
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={policyConfig.prefer_predicates}
                onChange={(e) => handleFieldChange('prefer_predicates', e.target.checked)}
              />
            }
            label="Prefer Predicate Proofs (Privacy-First)"
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4, mb: 2 }}>
            When enabled, predicates are preferred over raw values whenever possible
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={policyConfig.single_presentation}
                onChange={(e) => handleFieldChange('single_presentation', e.target.checked)}
              />
            }
            label="Require Single Presentation"
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            All claims must come from a single credential (more restrictive)
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ClaimsConfigurationStep;
