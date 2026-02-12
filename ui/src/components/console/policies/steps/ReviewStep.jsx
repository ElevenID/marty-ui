/**
 * Review Step
 * 
 * Final review of all policy configuration before submission.
 * Includes activation toggle and allows users to edit specific sections.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Divider,
  Grid,
  List,
  ListItem,
  ListItemText,
  Alert,
  FormControlLabel,
  Switch,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import TimerIcon from '@mui/icons-material/Timer';
import VerifiedIcon from '@mui/icons-material/Verified';
import { useTranslation } from 'react-i18next';

const ReviewStep = ({ data, onEdit, onToggleActivation }) => {
  const { t } = useTranslation('console');
  const { policyConfig, trustProfile, selectedTemplate, activateImmediately } = data;

  // Helper to format seconds to human-readable
  const formatDuration = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days} day${days > 1 ? 's' : ''}`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}`;
    return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  };

  const holderBindingLabels = {
    device_key: t('wizards.presentationPolicy.reviewStep.holderBindingLabels.device_key'),
    session_nonce: t('wizards.presentationPolicy.reviewStep.holderBindingLabels.session_nonce'),
    biometric: t('wizards.presentationPolicy.reviewStep.holderBindingLabels.biometric'),
    none: t('wizards.presentationPolicy.reviewStep.holderBindingLabels.none'),
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.presentationPolicy.reviewStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.presentationPolicy.reviewStep.description')}
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          {t('wizards.presentationPolicy.reviewStep.editHint')}
        </Typography>
      </Alert>

      {/* Basic Information */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <CheckCircleIcon sx={{ mr: 1 }} color="primary" />
              {t('wizards.presentationPolicy.reviewStep.sections.basicInformation')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              {t('wizards.presentationPolicy.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.policyName')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {policyConfig.name || <em>{t('wizards.presentationPolicy.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.description')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {policyConfig.description || <em>{t('wizards.presentationPolicy.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.purposeStatement')}
              </Typography>
              <Typography variant="body1">
                {policyConfig.purpose || <em>{t('wizards.presentationPolicy.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Trust Profile */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <SecurityIcon sx={{ mr: 1 }} color="primary" />
              {t('wizards.presentationPolicy.reviewStep.sections.trustProfile')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              {t('wizards.presentationPolicy.reviewStep.actions.edit')}
            </Button>
          </Box>

          {trustProfile ? (
            <Box>
              <Typography variant="body1" gutterBottom>
                {trustProfile.name}
              </Typography>
              <Chip
                label={trustProfile.trust_framework_type?.toUpperCase()}
                size="small"
                color="primary"
                sx={{ mr: 1 }}
              />
              {trustProfile.is_default && (
                <Chip label={t('wizards.presentationPolicy.trustProfileStep.defaultChip')} size="small" variant="outlined" />
              )}
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              <em>{t('wizards.presentationPolicy.reviewStep.values.noTrustProfile')}</em>
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Template */}
      {selectedTemplate && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Typography variant="h6">
                {t('wizards.presentationPolicy.reviewStep.sections.template')}
              </Typography>
              <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
                {t('wizards.presentationPolicy.reviewStep.actions.edit')}
              </Button>
            </Box>

            <Typography variant="body1" gutterBottom>
              {selectedTemplate.icon} {selectedTemplate.name}
            </Typography>
            {selectedTemplate.standardReference && (
              <Chip label={selectedTemplate.standardReference} size="small" variant="outlined" />
            )}
          </CardContent>
        </Card>
      )}

      {/* Credential Types & Claims */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6">
              {t('wizards.presentationPolicy.reviewStep.sections.credentialTypesClaims')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              {t('wizards.presentationPolicy.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            {t('wizards.presentationPolicy.reviewStep.fields.acceptedCredentialTypes')}
          </Typography>
          <Box sx={{ mb: 2 }}>
            {policyConfig.accepted_credential_types.length > 0 ? (
              policyConfig.accepted_credential_types.map((type) => (
                <Chip key={type} label={type} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
              ))
            ) : (
              <Typography variant="body2" color="text.secondary">
                <em>{t('wizards.presentationPolicy.reviewStep.values.noneSpecified')}</em>
              </Typography>
            )}
          </Box>

          <Divider sx={{ my: 2 }} />

          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            {t('wizards.presentationPolicy.reviewStep.fields.requiredClaims', { count: policyConfig.required_claims.length })}
          </Typography>
          <List dense>
            {policyConfig.required_claims.map((claim, index) => (
              <ListItem key={index}>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body2" component="span">
                        {claim.claim_name}
                      </Typography>
                      {claim.accept_predicate && (
                        <Chip label={t('wizards.presentationPolicy.reviewStep.values.predicateOk')} size="small" color="success" variant="outlined" />
                      )}
                    </Box>
                  }
                  secondary={t('wizards.presentationPolicy.reviewStep.values.fromCredentialType', {
                    type: claim.credential_type,
                  })}
                />
              </ListItem>
            ))}
          </List>

          {policyConfig.required_claims.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              <em>{t('wizards.presentationPolicy.reviewStep.values.noClaims')}</em>
            </Typography>
          )}

          <Divider sx={{ my: 2 }} />

          <Box sx={{ display: 'flex', gap: 1 }}>
            {policyConfig.prefer_predicates && (
              <Chip label={t('wizards.presentationPolicy.reviewStep.values.preferPredicates')} size="small" color="info" variant="outlined" />
            )}
            {policyConfig.single_presentation && (
              <Chip label={t('wizards.presentationPolicy.reviewStep.values.singlePresentation')} size="small" variant="outlined" />
            )}
          </Box>
        </CardContent>
      </Card>

      {/* Freshness & Binding */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <TimerIcon sx={{ mr: 1 }} color="primary" />
              {t('wizards.presentationPolicy.reviewStep.sections.freshnessSecurity')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
              {t('wizards.presentationPolicy.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.holderBinding')}
              </Typography>
              <Typography variant="body1">
                {holderBindingLabels[policyConfig.holder_binding] || policyConfig.holder_binding}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.revocationCheck')}
              </Typography>
              <Typography variant="body1">
                {policyConfig.freshness_requirements.require_revocation_check ? (
                  <Chip label={t('wizards.presentationPolicy.reviewStep.values.required')} size="small" color="success" />
                ) : (
                  <Chip label={t('wizards.presentationPolicy.reviewStep.values.notRequired')} size="small" />
                )}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.maxCredentialAge')}
              </Typography>
              <Typography variant="body1">
                {formatDuration(policyConfig.freshness_requirements.max_credential_age_seconds)}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.presentationPolicy.reviewStep.fields.maxProofAge')}
              </Typography>
              <Typography variant="body1">
                {formatDuration(policyConfig.freshness_requirements.max_proof_age_seconds)}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Standard Reference */}
      {policyConfig.metadata?.standard_reference && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
                <VerifiedIcon sx={{ mr: 1 }} color="primary" />
                {t('wizards.presentationPolicy.reviewStep.sections.complianceStandard')}
              </Typography>
              <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
                {t('wizards.presentationPolicy.reviewStep.actions.edit')}
              </Button>
            </Box>

            <Typography variant="body1">
              {policyConfig.metadata.standard_reference}
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Activation Toggle */}
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.reviewStep.sections.activation')}
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={activateImmediately}
                onChange={(e) => onToggleActivation(e.target.checked)}
                color="primary"
              />
            }
            label={t('wizards.presentationPolicy.reviewStep.activation.label')}
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            {activateImmediately
              ? t('wizards.presentationPolicy.reviewStep.activation.activeDescription')
              : t('wizards.presentationPolicy.reviewStep.activation.inactiveDescription')}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ReviewStep;
