/**
 * Review Step - Credential Template Wizard
 * 
 * Final review of all configuration before submission.
 * Allows editing and activation settings.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Grid,
  FormControlLabel,
  Switch,
  Divider,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DescriptionIcon from '@mui/icons-material/Description';
import SecurityIcon from '@mui/icons-material/Security';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import { useTranslation } from 'react-i18next';

const ReviewStep = ({ data, onChange, onEdit }) => {
  const { t } = useTranslation('console');
  const secondsToDays = (seconds) => Math.floor(seconds / 86400);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.credentialTemplate.reviewStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.credentialTemplate.reviewStep.description')}
      </Typography>

      {/* Basic Information */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CheckCircleIcon color="primary" />
              {t('wizards.credentialTemplate.reviewStep.sections.basicInformation')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              {t('wizards.credentialTemplate.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.templateName')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.name || <em>{t('wizards.credentialTemplate.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.credentialType')}
              </Typography>
              <Typography variant="body1">
                {data.credential_type}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.vct')}
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {data.vct}
              </Typography>
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('wizards.credentialTemplate.reviewStep.fields.description')}
                </Typography>
                <Typography variant="body1">
                  {data.description}
                </Typography>
              </Grid>
            )}
          </Grid>
        </CardContent>
      </Card>

      {/* Claims */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <DescriptionIcon color="primary" />
              {t('wizards.credentialTemplate.reviewStep.sections.claims', {
                count: data.claims?.length || 0,
              })}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              {t('wizards.credentialTemplate.reviewStep.actions.edit')}
            </Button>
          </Box>

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
        </CardContent>
      </Card>

      {/* Trust & Compliance */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="primary" />
              {t('wizards.credentialTemplate.reviewStep.sections.trustCompliance')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              {t('wizards.credentialTemplate.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.trustProfile')}
              </Typography>
              <Typography variant="body1">
                {data.trust_profile_id
                  ? t('wizards.credentialTemplate.reviewStep.values.trustProfileId', { id: data.trust_profile_id })
                  : <em>{t('wizards.credentialTemplate.reviewStep.values.notSelected')}</em>}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.complianceProfile')}
              </Typography>
              <Typography variant="body1">
                {data.compliance_profile_id || <em>{t('wizards.credentialTemplate.reviewStep.values.none')}</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Crypto & Validity */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <VpnKeyIcon color="primary" />
              {t('wizards.credentialTemplate.reviewStep.sections.cryptoValidity')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
              {t('wizards.credentialTemplate.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.signingAlgorithm')}
              </Typography>
              <Typography variant="body1">
                {data.signing_algorithm || 'ES256'}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.defaultValidity')}
              </Typography>
              <Typography variant="body1">
                {secondsToDays(data.validity_rules?.ttl_seconds || 31536000)} {t('wizards.credentialTemplate.reviewStep.values.days')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.maximumValidity')}
              </Typography>
              <Typography variant="body1">
                {secondsToDays(data.validity_rules?.max_validity_seconds || 63072000)} {t('wizards.credentialTemplate.reviewStep.values.days')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.fields.revocation')}
              </Typography>
              <Typography variant="body1">
                {data.revocation_profile_id || <em>{t('wizards.credentialTemplate.reviewStep.values.none')}</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Divider sx={{ my: 3 }} />

      {/* Activation Options */}
      <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, mb: 2 }}>
        <FormControlLabel
          control={
            <Switch
              checked={data.generate_artifacts_automatically !== false}
              onChange={(e) => onChange({ generate_artifacts_automatically: e.target.checked })}
            />
          }
          label={
            <Box>
              <Typography variant="subtitle2">
                {t('wizards.credentialTemplate.reviewStep.activationOptions.generateArtifacts.label')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.activationOptions.generateArtifacts.description')}
              </Typography>
            </Box>
          }
        />
      </Box>

      <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <FormControlLabel
          control={
            <Switch
              checked={data.activate_immediately !== false}
              onChange={(e) => onChange({ activate_immediately: e.target.checked })}
            />
          }
          label={
            <Box>
              <Typography variant="subtitle2">
                {t('wizards.credentialTemplate.reviewStep.activationOptions.activateImmediately.label')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('wizards.credentialTemplate.reviewStep.activationOptions.activateImmediately.description')}
              </Typography>
            </Box>
          }
        />
      </Box>
    </Box>
  );
};

export default ReviewStep;
