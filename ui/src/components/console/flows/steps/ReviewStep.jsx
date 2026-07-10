/**
 * Review Step
 * 
 * Final review of all flow configuration before submission.
 * Includes activation toggle and allows users to edit specific sections.
 */

import {
  Box,
  Typography,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemText,
  Alert,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import DeployIcon from '@mui/icons-material/RocketLaunch';
import GppGoodIcon from '@mui/icons-material/GppGood';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import VerifiedIcon from '@mui/icons-material/Verified';
import { useTranslation } from 'react-i18next';
import { ReviewSectionCard, ReviewActivationCard, ReviewField } from '../../../common';

const PRECONDITION_ICONS = {
  application_approved: <CheckCircleIcon />,
  identity_verified: <GppGoodIcon />,
  manual_admin_approval: <AdminPanelSettingsIcon />,
  external_verification: <VerifiedIcon />,
};

const ReviewStep = ({ data, onEdit, onToggleActivation }) => {
  const { t } = useTranslation('console');
  const { 
    flowType, 
    name, 
    description, 
    flowSteps, 
    preconditions = [],
    selectedDeployment, 
    defaultPolicyId, 
    credentialTemplateId,
    activateImmediately 
  } = data;

  const FLOW_TYPE_LABELS = {
    verification: t('wizards.flowDefinition.reviewStep.flowTypeLabels.verification'),
    issuance: t('wizards.flowDefinition.reviewStep.flowTypeLabels.issuance'),
    issuance_oid4vci: t('wizards.flowDefinition.reviewStep.flowTypeLabels.issuance_oid4vci'),
    combined: t('wizards.flowDefinition.reviewStep.flowTypeLabels.combined'),
  };

  const PRECONDITION_LABELS = {
    application_approved: t('wizards.flowDefinition.preconditionsStep.types.application_approved.label'),
    identity_verified: t('wizards.flowDefinition.preconditionsStep.types.identity_verified.label'),
    manual_admin_approval: t('wizards.flowDefinition.preconditionsStep.types.manual_admin_approval.label'),
    external_verification: t('wizards.flowDefinition.preconditionsStep.types.external_verification.label'),
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.flowDefinition.reviewStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.flowDefinition.reviewStep.description')}
      </Typography>

      {/* Basic Information */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.flowDefinition.reviewStep.sections.basicInfo')}
        icon={<CheckCircleIcon color="primary" />}
        onEdit={() => onEdit(1)}
        editLabel={t('wizards.flowDefinition.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <ReviewField
                label={t('wizards.flowDefinition.reviewStep.fields.flowType')}
                value={FLOW_TYPE_LABELS[flowType] || flowType}
                gutterBottom
              />
            </Grid>

            <Grid item xs={12} sm={6}>
              <ReviewField
                label={t('wizards.flowDefinition.reviewStep.fields.flowName')}
                value={name}
                placeholder={t('wizards.flowDefinition.reviewStep.values.notSet')}
                gutterBottom
              />
            </Grid>

            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.flowDefinition.reviewStep.fields.description')}
                value={description}
                placeholder={t('wizards.flowDefinition.reviewStep.values.notSet')}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Flow Steps */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.flowDefinition.reviewStep.sections.flowSteps', { count: flowSteps.length })}
        icon={<AccountTreeIcon color="primary" />}
        onEdit={() => onEdit(1)}
        editLabel={t('wizards.flowDefinition.reviewStep.actions.edit')}
      >
          {flowSteps.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              <em>{t('wizards.flowDefinition.reviewStep.values.noSteps')}</em>
            </Typography>
          ) : (
            <List dense>
              {flowSteps.map((step, index) => (
                <ListItem key={index}>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Chip label={index + 1} size="small" color="primary" />
                        <Typography variant="body2" component="span">
                          {step.name}
                        </Typography>
                      </Box>
                    }
                    secondary={t('wizards.flowDefinition.reviewStep.fields.stepType', { type: step.type })}
                  />
                </ListItem>
              ))}
            </List>
          )}
      </ReviewSectionCard>

      {/* Preconditions */}
      {flowType === 'issuance_oid4vci' && (
        <ReviewSectionCard
          sx={{ mb: 2 }}
          title={t('wizards.flowDefinition.reviewStep.sections.preconditions', { count: preconditions.length })}
          icon={<CheckCircleIcon color="primary" />}
          onEdit={() => onEdit(2)}
          editLabel={t('wizards.flowDefinition.reviewStep.actions.edit')}
        >
            {preconditions.length === 0 ? (
              <Alert severity="warning">
                <Typography variant="body2">
                  {t('wizards.flowDefinition.reviewStep.values.noPreconditions')}
                </Typography>
              </Alert>
            ) : (
              <List dense>
                {preconditions.map((condition, index) => (
                  <ListItem key={index}>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {PRECONDITION_ICONS[condition] || <CheckCircleIcon />}
                          <Typography variant="body2" component="span">
                            {PRECONDITION_LABELS[condition] || condition}
                          </Typography>
                        </Box>
                      }
                      secondary={t('wizards.flowDefinition.preconditionsStep.conditionCounter', {
                        index: index + 1,
                        total: preconditions.length,
                      })}
                    />
                  </ListItem>
                ))}
              </List>
            )}
        </ReviewSectionCard>
      )}

      {/* Deployment Binding */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.flowDefinition.reviewStep.sections.deploymentBinding')}
        icon={<DeployIcon color="primary" />}
        onEdit={() => onEdit(3)}
        editLabel={t('wizards.flowDefinition.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.flowDefinition.reviewStep.fields.deploymentProfile')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {selectedDeployment ? (
                  <>
                    {selectedDeployment.name}
                    {selectedDeployment.is_active && (
                      <Chip
                        label={t('wizards.flowDefinition.reviewStep.values.activeChip')}
                        size="small"
                        color="success"
                        variant="outlined"
                        sx={{ ml: 1 }}
                      />
                    )}
                  </>
                ) : (
                  <em>{t('wizards.flowDefinition.reviewStep.values.noneConfigureLater')}</em>
                )}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.flowDefinition.reviewStep.fields.defaultPolicy')}
                value={defaultPolicyId ? t('wizards.flowDefinition.reviewStep.fields.policyId', { id: defaultPolicyId }) : undefined}
                placeholder={t('wizards.flowDefinition.reviewStep.values.noneConfigureLater')}
              />
            </Grid>

            <Grid item xs={12}>
              <ReviewField
                label="Credential Template"
                value={credentialTemplateId || undefined}
                placeholder={t('wizards.flowDefinition.reviewStep.values.noneConfigureLater')}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Activation Toggle */}
      <ReviewActivationCard
        title={t('wizards.flowDefinition.reviewStep.sections.activation')}
        label={t('wizards.flowDefinition.reviewStep.activation.label')}
        checked={activateImmediately}
        onChange={(e) => onToggleActivation(e.target.checked)}
        activeDescription={t('wizards.flowDefinition.reviewStep.activation.activeDescription')}
        inactiveDescription={t('wizards.flowDefinition.reviewStep.activation.inactiveDescription')}
      />
    </Box>
  );
};

export default ReviewStep;
