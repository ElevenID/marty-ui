/**
 * Review Step
 * 
 * Final review of all policy configuration before submission.
 * Includes activation toggle and allows users to edit specific sections.
 */

import {
  Box,
  Typography,
  Chip,
  Divider,
  Grid,
  List,
  ListItem,
  ListItemText,
  Alert,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import TimerIcon from '@mui/icons-material/Timer';
import VerifiedIcon from '@mui/icons-material/Verified';
import { useTranslation } from 'react-i18next';
import { ReviewSectionCard, ReviewActivationCard, ReviewField } from '../../../common';

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
    session_binding: t('wizards.presentationPolicy.reviewStep.holderBindingLabels.session_binding'),
    credential_key: t('wizards.presentationPolicy.reviewStep.holderBindingLabels.credential_key'),
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
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.presentationPolicy.reviewStep.sections.basicInformation')}
        icon={<CheckCircleIcon color="primary" />}
        onEdit={() => onEdit(2)}
        editLabel={t('wizards.presentationPolicy.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.presentationPolicy.reviewStep.fields.policyName')}
                value={policyConfig.name}
                placeholder={t('wizards.presentationPolicy.reviewStep.values.notSet')}
                gutterBottom
              />
            </Grid>

            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.presentationPolicy.reviewStep.fields.description')}
                value={policyConfig.description}
                placeholder={t('wizards.presentationPolicy.reviewStep.values.notSet')}
                gutterBottom
              />
            </Grid>

            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.presentationPolicy.reviewStep.fields.purposeStatement')}
                value={policyConfig.purpose}
                placeholder={t('wizards.presentationPolicy.reviewStep.values.notSet')}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Trust Profile */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.presentationPolicy.reviewStep.sections.trustProfile')}
        icon={<SecurityIcon color="primary" />}
        onEdit={() => onEdit(0)}
        editLabel={t('wizards.presentationPolicy.reviewStep.actions.edit')}
      >
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
      </ReviewSectionCard>

      {/* Template */}
      {selectedTemplate && (
        <ReviewSectionCard
          sx={{ mb: 2 }}
          title={t('wizards.presentationPolicy.reviewStep.sections.template')}
          onEdit={() => onEdit(1)}
          editLabel={t('wizards.presentationPolicy.reviewStep.actions.edit')}
        >
            <Typography variant="body1" gutterBottom>
              {selectedTemplate.icon} {selectedTemplate.name}
            </Typography>
            {selectedTemplate.standardReference && (
              <Chip label={selectedTemplate.standardReference} size="small" variant="outlined" />
            )}
        </ReviewSectionCard>
      )}

      {/* Credential Types & Claims */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.presentationPolicy.reviewStep.sections.credentialTypesClaims')}
        onEdit={() => onEdit(2)}
        editLabel={t('wizards.presentationPolicy.reviewStep.actions.edit')}
      >
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
      </ReviewSectionCard>

      {/* Freshness & Binding */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.presentationPolicy.reviewStep.sections.freshnessSecurity')}
        icon={<TimerIcon color="primary" />}
        onEdit={() => onEdit(3)}
        editLabel={t('wizards.presentationPolicy.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <ReviewField
                label={t('wizards.presentationPolicy.reviewStep.fields.holderBinding')}
                value={holderBindingLabels[policyConfig.holder_binding] || policyConfig.holder_binding}
              />
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
              <ReviewField
                label={t('wizards.presentationPolicy.reviewStep.fields.maxCredentialAge')}
                value={formatDuration(policyConfig.freshness_requirements.max_credential_age_seconds)}
              />
            </Grid>

            <Grid item xs={12} sm={6}>
              <ReviewField
                label={t('wizards.presentationPolicy.reviewStep.fields.maxProofAge')}
                value={formatDuration(policyConfig.freshness_requirements.max_proof_age_seconds)}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Standard Reference */}
      {policyConfig.metadata?.standard_reference && (
        <ReviewSectionCard
          sx={{ mb: 2 }}
          title={t('wizards.presentationPolicy.reviewStep.sections.complianceStandard')}
          icon={<VerifiedIcon color="primary" />}
          onEdit={() => onEdit(3)}
          editLabel={t('wizards.presentationPolicy.reviewStep.actions.edit')}
        >
            <Typography variant="body1">
              {policyConfig.metadata.standard_reference}
            </Typography>
        </ReviewSectionCard>
      )}

      {/* Activation Toggle */}
      <ReviewActivationCard
        title={t('wizards.presentationPolicy.reviewStep.sections.activation')}
        label={t('wizards.presentationPolicy.reviewStep.activation.label')}
        checked={activateImmediately}
        onChange={(e) => onToggleActivation(e.target.checked)}
        activeDescription={t('wizards.presentationPolicy.reviewStep.activation.activeDescription')}
        inactiveDescription={t('wizards.presentationPolicy.reviewStep.activation.inactiveDescription')}
      />
    </Box>
  );
};

export default ReviewStep;
