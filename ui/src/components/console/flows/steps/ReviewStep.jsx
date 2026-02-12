/**
 * Review Step
 * 
 * Final review of all flow configuration before submission.
 * Includes activation toggle and allows users to edit specific sections.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemText,
  FormControlLabel,
  Switch,
  Alert,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import DeployIcon from '@mui/icons-material/RocketLaunch';
import GppGoodIcon from '@mui/icons-material/GppGood';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import VerifiedIcon from '@mui/icons-material/Verified';
import { useTranslation } from 'react-i18next';

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
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <CheckCircleIcon sx={{ mr: 1 }} color="primary" />
              {t('wizards.flowDefinition.reviewStep.sections.basicInfo')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              {t('wizards.flowDefinition.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.flowDefinition.reviewStep.fields.flowType')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {FLOW_TYPE_LABELS[flowType] || flowType}
              </Typography>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.flowDefinition.reviewStep.fields.flowName')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {name || <em>{t('wizards.flowDefinition.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.flowDefinition.reviewStep.fields.description')}
              </Typography>
              <Typography variant="body1">
                {description || <em>{t('wizards.flowDefinition.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Flow Steps */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <AccountTreeIcon sx={{ mr: 1 }} color="primary" />
              {t('wizards.flowDefinition.reviewStep.sections.flowSteps', { count: flowSteps.length })}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              {t('wizards.flowDefinition.reviewStep.actions.edit')}
            </Button>
          </Box>

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
        </CardContent>
      </Card>

      {/* Preconditions */}
      {flowType === 'issuance_oid4vci' && (
        <Card sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
              <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
                <CheckCircleIcon sx={{ mr: 1 }} color="primary" />
                {t('wizards.flowDefinition.reviewStep.sections.preconditions', { count: preconditions.length })}
              </Typography>
              <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
                {t('wizards.flowDefinition.reviewStep.actions.edit')}
              </Button>
            </Box>

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
          </CardContent>
        </Card>
      )}

      {/* Deployment Binding */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <DeployIcon sx={{ mr: 1 }} color="primary" />
              {t('wizards.flowDefinition.reviewStep.sections.deploymentBinding')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(3)}>
              {t('wizards.flowDefinition.reviewStep.actions.edit')}
            </Button>
          </Box>

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
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.flowDefinition.reviewStep.fields.defaultPolicy')}
              </Typography>
              <Typography variant="body1">
                {defaultPolicyId ? (
                  t('wizards.flowDefinition.reviewStep.fields.policyId', { id: defaultPolicyId })
                ) : (
                  <em>{t('wizards.flowDefinition.reviewStep.values.noneConfigureLater')}</em>
                )}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Activation Toggle */}
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.flowDefinition.reviewStep.sections.activation')}
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={activateImmediately}
                onChange={(e) => onToggleActivation(e.target.checked)}
                color="primary"
              />
            }
            label={t('wizards.flowDefinition.reviewStep.activation.label')}
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            {activateImmediately
              ? t('wizards.flowDefinition.reviewStep.activation.activeDescription')
              : t('wizards.flowDefinition.reviewStep.activation.inactiveDescription')}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ReviewStep;
