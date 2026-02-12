import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Button,
  Typography,
  Alert,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { useWizard } from '../../../hooks/useWizard';
import { useNotifications } from '../../../hooks/useNotifications';

const getSetupSteps = (t) => [
  {
    label: t('dashboard.guidedSetup.steps.trustProfile.label'),
    description: t('dashboard.guidedSetup.steps.trustProfile.description'),
    quickFields: ['name', 'description'],
    fullPath: '/console/trust/profiles/new',
  },
  {
    label: t('dashboard.guidedSetup.steps.credentialTemplate.label'),
    description: t('dashboard.guidedSetup.steps.credentialTemplate.description'),
    quickFields: ['name', 'credentialType'],
    fullPath: '/console/templates/credentials/new',
  },
  {
    label: t('dashboard.guidedSetup.steps.presentationPolicy.label'),
    description: t('dashboard.guidedSetup.steps.presentationPolicy.description'),
    quickFields: ['name', 'requiredCredentials'],
    fullPath: '/console/policies/presentation/new',
  },
  {
    label: t('dashboard.guidedSetup.steps.deploymentProfile.label'),
    description: t('dashboard.guidedSetup.steps.deploymentProfile.description'),
    quickFields: ['name', 'environment'],
    fullPath: '/console/deploy/profiles/new',
  },
  {
    label: t('dashboard.guidedSetup.steps.flowDefinition.label'),
    description: t('dashboard.guidedSetup.steps.flowDefinition.description'),
    quickFields: ['name', 'flowType'],
    fullPath: '/console/flows/definitions/new',
  },
];

/**
 * GuidedSetupWizard - Multi-step wizard for initial organization setup
 * 
 * Provides quick-create forms for each essential resource type.
 * Users can either use quick forms or jump to advanced editors.
 * Progress is persisted in localStorage.
 */
function GuidedSetupWizard() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { showNotification } = useNotifications();
  const [activeStep, setActiveStep] = useState(0);
  const [completed, setCompleted] = useState({});
  const [formData, setFormData] = useState({});

  // Load progress from localStorage on mount
  useEffect(() => {
    const savedProgress = localStorage.getItem('guided-setup-progress');
    if (savedProgress) {
      try {
        const { activeStep: savedStep, completed: savedCompleted, formData: savedData } = JSON.parse(savedProgress);
        setActiveStep(savedStep || 0);
        setCompleted(savedCompleted || {});
        setFormData(savedData || {});
      } catch (err) {
        console.error('Failed to load setup progress:', err);
      }
    }
  }, []);

  // Save progress to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('guided-setup-progress', JSON.stringify({
      activeStep,
      completed,
      formData,
    }));
  }, [activeStep, completed, formData]);

  const handleNext = () => {
    setActiveStep((prev) => prev + 1);
  };

  const handleBack = () => {
    setActiveStep((prev) => prev - 1);
  };

  const handleStepComplete = (stepIndex) => {
    setCompleted((prev) => ({ ...prev, [stepIndex]: true }));
    if (stepIndex < SETUP_STEPS.length - 1) {
      handleNext();
    }
  };

  const handleSkipStep = (stepIndex) => {
    if (stepIndex < SETUP_STEPS.length - 1) {
      handleNext();
    }
  };

  const handleFinish = () => {
    localStorage.removeItem('guided-setup-progress');
    sessionStorage.removeItem('setup-banner-dismissed');
    showNotification?.(t('dashboard.guidedSetup.setupCompletedNotification'), 'success');
    navigate('/console');
  };

  const handleCancel = () => {
    if (confirm(t('dashboard.guidedSetup.exitConfirm'))) {
      navigate('/console');
    }
  };

  const SETUP_STEPS = getSetupSteps(t);
  const totalSteps = SETUP_STEPS.length;
  const completedCount = Object.keys(completed).length;
  const allComplete = completedCount === totalSteps;

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', py: 4 }}>
      <Paper sx={{ p: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            {t('dashboard.guidedSetup.title')}
          </Typography>
          <Typography variant="body1" color="text.secondary" paragraph>
            {t('dashboard.guidedSetup.welcomeMessage')}
          </Typography>
          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>{t('dashboard.guidedSetup.progressSaved')}</strong> {t('dashboard.guidedSetup.progressSavedDescription')}
            </Typography>
          </Alert>
        </Box>

        {/* Progress Summary */}
        <Box sx={{ mb: 4, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary">
            {t('dashboard.guidedSetup.progressCount', { completed: completedCount, total: totalSteps })}
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={activeStep} orientation="vertical">
          {SETUP_STEPS.map((step, index) => (
            <Step key={step.label} completed={completed[index]}>
              <StepLabel
                optional={
                  completed[index] ? (
                    <Typography variant="caption" color="success.main">
                      <CheckCircleIcon fontSize="small" sx={{ verticalAlign: 'middle', mr: 0.5 }} />
                      {t('dashboard.guidedSetup.stepComplete')}
                    </Typography>
                  ) : null
                }
              >
                {step.label}
              </StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {step.description}
                </Typography>

                <QuickCreateForm
                  step={step}
                  stepIndex={index}
                  formData={formData[index] || {}}
                  onDataChange={(data) => {
                    setFormData((prev) => ({ ...prev, [index]: data }));
                  }}
                />

                <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    onClick={() => handleStepComplete(index)}
                    endIcon={<ArrowForwardIcon />}
                  >
                    {index === totalSteps - 1 ? t('dashboard.guidedSetup.completeSetup') : t('dashboard.guidedSetup.continue')}
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => handleSkipStep(index)}
                  >
                    {t('dashboard.guidedSetup.skipForNow')}
                  </Button>
                  <Button
                    variant="text"
                    href={step.fullPath}
                    target="_blank"
                    endIcon={<OpenInNewIcon />}
                  >
                    {t('dashboard.guidedSetup.advancedEditor')}
                  </Button>
                  {index > 0 && (
                    <Button
                      variant="text"
                      onClick={handleBack}
                      startIcon={<ArrowBackIcon />}
                    >
                      {t('dashboard.guidedSetup.back')}
                    </Button>
                  )}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>

        {/* Completion Screen */}
        {allComplete && (
          <Box sx={{ mt: 4, p: 3, bgcolor: 'success.light', borderRadius: 1 }}>
            <Typography variant="h6" gutterBottom>
              {t('dashboard.guidedSetup.setupCompleteTitle')}
            </Typography>
            <Typography variant="body2" paragraph>
              {t('dashboard.guidedSetup.setupCompleteMessage')}
            </Typography>
            <Button variant="contained" onClick={handleFinish}>
              {t('dashboard.guidedSetup.goToDashboard')}
            </Button>
          </Box>
        )}

        {/* Footer Actions */}
        {!allComplete && (
          <Box sx={{ mt: 4, pt: 3, borderTop: 1, borderColor: 'divider', display: 'flex', justifyContent: 'space-between' }}>
            <Button variant="text" onClick={handleCancel}>
              {t('dashboard.guidedSetup.exitWizard')}
            </Button>
            <Typography variant="caption" color="text.secondary">
              {t('dashboard.guidedSetup.progressAutoSaved')}
            </Typography>
          </Box>
        )}
      </Paper>
    </Box>
  );
}

/**
 * Quick create form for each step
 */
function QuickCreateForm({ step, stepIndex, formData, onDataChange }) {
  const { t } = useTranslation('console');
  
  const handleChange = (field, value) => {
    onDataChange({ ...formData, [field]: value });
  };

  // Render quick form fields based on step
  const renderFields = () => {
    switch (stepIndex) {
      case 0: // Trust Profile
        return (
          <>
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.trustProfile.nameLabel')}
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder={t('dashboard.guidedSetup.steps.trustProfile.namePlaceholder')}
            />
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.trustProfile.descriptionLabel')}
              value={formData.description || ''}
              onChange={(e) => handleChange('description', e.target.value)}
              margin="normal"
              multiline
              rows={2}
              placeholder={t('dashboard.guidedSetup.steps.trustProfile.descriptionPlaceholder')}
            />
          </>
        );

      case 1: // Credential Template
        return (
          <>
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.credentialTemplate.nameLabel')}
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder={t('dashboard.guidedSetup.steps.credentialTemplate.namePlaceholder')}
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>{t('dashboard.guidedSetup.steps.credentialTemplate.typeLabel')}</InputLabel>
              <Select
                value={formData.credentialType || ''}
                label={t('dashboard.guidedSetup.steps.credentialTemplate.typeLabel')}
                onChange={(e) => handleChange('credentialType', e.target.value)}
              >
                <MenuItem value="VerifiableCredential">{t('dashboard.guidedSetup.steps.credentialTemplate.typeVC')}</MenuItem>
                <MenuItem value="mDL">{t('dashboard.guidedSetup.steps.credentialTemplate.typeMDL')}</MenuItem>
                <MenuItem value="OpenBadge">{t('dashboard.guidedSetup.steps.credentialTemplate.typeBadge')}</MenuItem>
              </Select>
            </FormControl>
          </>
        );

      case 2: // Presentation Policy
        return (
          <>
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.presentationPolicy.nameLabel')}
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder={t('dashboard.guidedSetup.steps.presentationPolicy.namePlaceholder')}
            />
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.presentationPolicy.requiredLabel')}
              value={formData.requiredCredentials || ''}
              onChange={(e) => handleChange('requiredCredentials', e.target.value)}
              margin="normal"
              placeholder={t('dashboard.guidedSetup.steps.presentationPolicy.requiredPlaceholder')}
              helperText={t('dashboard.guidedSetup.steps.presentationPolicy.requiredHelper')}
            />
          </>
        );

      case 3: // Deployment Profile
        return (
          <>
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.deploymentProfile.nameLabel')}
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder={t('dashboard.guidedSetup.steps.deploymentProfile.namePlaceholder')}
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>{t('dashboard.guidedSetup.steps.deploymentProfile.environmentLabel')}</InputLabel>
              <Select
                value={formData.environment || 'development'}
                label={t('dashboard.guidedSetup.steps.deploymentProfile.environmentLabel')}
                onChange={(e) => handleChange('environment', e.target.value)}
              >
                <MenuItem value="development">{t('dashboard.guidedSetup.steps.deploymentProfile.envDevelopment')}</MenuItem>
                <MenuItem value="staging">{t('dashboard.guidedSetup.steps.deploymentProfile.envStaging')}</MenuItem>
                <MenuItem value="production">{t('dashboard.guidedSetup.steps.deploymentProfile.envProduction')}</MenuItem>
              </Select>
            </FormControl>
          </>
        );

      case 4: // Flow Definition
        return (
          <>
            <TextField
              fullWidth
              label={t('dashboard.guidedSetup.steps.flowDefinition.nameLabel')}
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder={t('dashboard.guidedSetup.steps.flowDefinition.namePlaceholder')}
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>{t('dashboard.guidedSetup.steps.flowDefinition.typeLabel')}</InputLabel>
              <Select
                value={formData.flowType || ''}
                label={t('dashboard.guidedSetup.steps.flowDefinition.typeLabel')}
                onChange={(e) => handleChange('flowType', e.target.value)}
              >
                <MenuItem value="verification">{t('dashboard.guidedSetup.steps.flowDefinition.typeVerification')}</MenuItem>
                <MenuItem value="issuance">{t('dashboard.guidedSetup.steps.flowDefinition.typeIssuance')}</MenuItem>
                <MenuItem value="combined">{t('dashboard.guidedSetup.steps.flowDefinition.typeCombined')}</MenuItem>
              </Select>
            </FormControl>
          </>
        );

      default:
        return null;
    }
  };

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="subtitle2" gutterBottom>
        {t('dashboard.guidedSetup.quickCreateTitle')}
      </Typography>
      {renderFields()}
    </Box>
  );
}

export default GuidedSetupWizard;
