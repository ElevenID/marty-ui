/**
 * Review Step - Credential Template Wizard
 * 
 * Final review of all configuration before submission.
 * Allows editing and activation settings.
 */

import {
  Box,
  Typography,
  Chip,
  Grid,
  Divider,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DescriptionIcon from '@mui/icons-material/Description';
import SecurityIcon from '@mui/icons-material/Security';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import { useTranslation } from 'react-i18next';
import { ReviewSectionCard, ReviewToggleOption, ReviewField } from '../../../common';
import { credentialTemplateValidity } from '../credentialTemplateValidity';

const ReviewStep = ({ data, onChange, onEdit }) => {
  const { t } = useTranslation('console');
  const { values } = credentialTemplateValidity(data.validity_rules);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.credentialTemplate.reviewStep.title')}
      </Typography>
      <Typography color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
        {t('wizards.credentialTemplate.reviewStep.description')}
      </Typography>

      {/* Basic Information */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.credentialTemplate.reviewStep.sections.basicInformation')}
        icon={<CheckCircleIcon color="primary" />}
        onEdit={() => onEdit(0)}
        editLabel={t('wizards.credentialTemplate.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid size={12}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.templateName')}
                value={data.name}
                placeholder={t('wizards.credentialTemplate.reviewStep.values.notSet')}
                gutterBottom
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.credentialType')}
                value={data.credential_type}
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.vct')}
                value={data.vct}
                valueSx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}
              />
            </Grid>

            {data.description && (
              <Grid size={12}>
                <ReviewField
                  label={t('wizards.credentialTemplate.reviewStep.fields.description')}
                  value={data.description}
                />
              </Grid>
            )}
          </Grid>
      </ReviewSectionCard>

      {/* Claims */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.credentialTemplate.reviewStep.sections.claims', {
          count: data.claims?.length || 0,
        })}
        icon={<DescriptionIcon color="primary" />}
        onEdit={() => onEdit(1)}
        editLabel={t('wizards.credentialTemplate.reviewStep.actions.edit')}
      >
          {data.claims && data.claims.length > 0 ? (
            <List dense>
              {data.claims.map((claim, index) => (
                <ListItem key={index} sx={{ px: 0 }}>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography
                          variant="body2"
                          sx={{ fontFamily: 'monospace', fontWeight: 'medium' }}
                        >
                          {claim.name}
                        </Typography>
                        <Chip label={claim.type} size="small" />
                        {claim.required && (
                          <Chip label={t('wizards.credentialTemplate.claimsStep.addClaim.requiredLabel')} size="small" color="primary" />
                        )}
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <Typography variant="body2" color="text.secondary">
                {t('wizards.credentialTemplate.claimsStep.noClaimsDefined')}
            </Typography>
          )}
      </ReviewSectionCard>

      {/* Trust & Compliance */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.credentialTemplate.reviewStep.sections.trustCompliance')}
        icon={<SecurityIcon color="primary" />}
        onEdit={() => onEdit(2)}
        editLabel={t('wizards.credentialTemplate.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.trustProfile')}
                value={data.trust_profile_id
                  ? t('wizards.credentialTemplate.reviewStep.values.trustProfileId', { id: data.trust_profile_id })
                  : undefined}
                placeholder={t('wizards.credentialTemplate.reviewStep.values.notSelected')}
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.complianceProfile')}
                value={data.compliance_profile_id}
                placeholder={t('wizards.credentialTemplate.reviewStep.values.none')}
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label="Issuer DID"
                value={data.issuer_did || undefined}
                placeholder="Required before activation"
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Crypto & Validity */}
      <ReviewSectionCard
        sx={{ mb: 3 }}
        title={t('wizards.credentialTemplate.reviewStep.sections.cryptoValidity')}
        icon={<VpnKeyIcon color="primary" />}
        onEdit={() => onEdit(3)}
        editLabel={t('wizards.credentialTemplate.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.defaultValidity')}
                value={`${values.default_validity_days} ${t('wizards.credentialTemplate.reviewStep.values.days')}`}
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.maximumValidity')}
                value={`${values.max_validity_days} ${t('wizards.credentialTemplate.reviewStep.values.days')}`}
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.cryptoValidityStep.validity.notBeforeOffset')}
                value={String(values.not_before_offset_seconds)}
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <ReviewField
                label={t('wizards.credentialTemplate.reviewStep.fields.revocation')}
                value={data.revocation_profile_id}
                placeholder={t('wizards.credentialTemplate.reviewStep.values.none')}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      <Divider sx={{ my: 3 }} />

      {/* Activation Options */}
      <ReviewToggleOption
        checked={data.activate_immediately !== false}
        onChange={(e) => onChange({ activate_immediately: e.target.checked })}
        title={t('wizards.credentialTemplate.reviewStep.activationOptions.activateImmediately.label')}
        description={t('wizards.credentialTemplate.reviewStep.activationOptions.activateImmediately.description')}
      />
    </Box>
  );
};

export default ReviewStep;
