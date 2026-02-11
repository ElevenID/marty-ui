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
import { useNavigate } from 'react-router-dom';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { useWizard } from '../../../hooks/useWizard';
import { useNotifications } from '../../../hooks/useNotifications';

const SETUP_STEPS = [
  {
    label: 'Trust Profile',
    description: 'Define which credential issuers and formats you trust',
    quickFields: ['name', 'description'],
    fullPath: '/console/trust/profiles/new',
  },
  {
    label: 'Credential Template',
    description: 'Create a template for credentials you will issue',
    quickFields: ['name', 'credentialType'],
    fullPath: '/console/templates/credentials/new',
  },
  {
    label: 'Presentation Policy',
    description: 'Define what credentials users must present',
    quickFields: ['name', 'requiredCredentials'],
    fullPath: '/console/policies/presentation/new',
  },
  {
    label: 'Deployment Profile',
    description: 'Configure your runtime environment',
    quickFields: ['name', 'environment'],
    fullPath: '/console/deploy/profiles/new',
  },
  {
    label: 'Flow Definition',
    description: 'Create a workflow for issuance or verification',
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
    showNotification?.('Setup completed! Your organization is ready to use.', 'success');
    navigate('/console');
  };

  const handleCancel = () => {
    if (confirm('Are you sure you want to exit the setup wizard? Your progress will be saved.')) {
      navigate('/console');
    }
  };

  const totalSteps = SETUP_STEPS.length;
  const completedCount = Object.keys(completed).length;
  const allComplete = completedCount === totalSteps;

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', py: 4 }}>
      <Paper sx={{ p: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Guided Organization Setup
          </Typography>
          <Typography variant="body1" color="text.secondary" paragraph>
            Welcome! This wizard will help you set up the essential components for your organization.
            You can use quick forms here or click "Advanced" for full configuration.
          </Typography>
          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Progress is automatically saved.</strong> You can exit and resume anytime.
            </Typography>
          </Alert>
        </Box>

        {/* Progress Summary */}
        <Box sx={{ mb: 4, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Progress: {completedCount} of {totalSteps} steps completed
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
                      Complete
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
                    {index === totalSteps - 1 ? 'Complete Setup' : 'Continue'}
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => handleSkipStep(index)}
                  >
                    Skip for Now
                  </Button>
                  <Button
                    variant="text"
                    href={step.fullPath}
                    target="_blank"
                    endIcon={<OpenInNewIcon />}
                  >
                    Advanced Editor
                  </Button>
                  {index > 0 && (
                    <Button
                      variant="text"
                      onClick={handleBack}
                      startIcon={<ArrowBackIcon />}
                    >
                      Back
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
              🎉 Setup Complete!
            </Typography>
            <Typography variant="body2" paragraph>
              You've configured all the essential components. Your organization is now ready to issue and verify credentials.
            </Typography>
            <Button variant="contained" onClick={handleFinish}>
              Go to Dashboard
            </Button>
          </Box>
        )}

        {/* Footer Actions */}
        {!allComplete && (
          <Box sx={{ mt: 4, pt: 3, borderTop: 1, borderColor: 'divider', display: 'flex', justifyContent: 'space-between' }}>
            <Button variant="text" onClick={handleCancel}>
              Exit Wizard
            </Button>
            <Typography variant="caption" color="text.secondary">
              Your progress is saved automatically
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
              label="Trust Profile Name"
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder="e.g., Production Trust Profile"
            />
            <TextField
              fullWidth
              label="Description"
              value={formData.description || ''}
              onChange={(e) => handleChange('description', e.target.value)}
              margin="normal"
              multiline
              rows={2}
              placeholder="Describe which issuers and formats are trusted"
            />
          </>
        );

      case 1: // Credential Template
        return (
          <>
            <TextField
              fullWidth
              label="Template Name"
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder="e.g., Employee Badge"
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>Credential Type</InputLabel>
              <Select
                value={formData.credentialType || ''}
                label="Credential Type"
                onChange={(e) => handleChange('credentialType', e.target.value)}
              >
                <MenuItem value="VerifiableCredential">Verifiable Credential (W3C)</MenuItem>
                <MenuItem value="mDL">Mobile Driver's License (ISO 18013-5)</MenuItem>
                <MenuItem value="OpenBadge">Open Badge</MenuItem>
              </Select>
            </FormControl>
          </>
        );

      case 2: // Presentation Policy
        return (
          <>
            <TextField
              fullWidth
              label="Policy Name"
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder="e.g., Age Verification Policy"
            />
            <TextField
              fullWidth
              label="Required Credentials"
              value={formData.requiredCredentials || ''}
              onChange={(e) => handleChange('requiredCredentials', e.target.value)}
              margin="normal"
              placeholder="e.g., Driver's License, Passport"
              helperText="Comma-separated list of credential types"
            />
          </>
        );

      case 3: // Deployment Profile
        return (
          <>
            <TextField
              fullWidth
              label="Profile Name"
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder="e.g., Production Deployment"
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>Environment</InputLabel>
              <Select
                value={formData.environment || 'development'}
                label="Environment"
                onChange={(e) => handleChange('environment', e.target.value)}
              >
                <MenuItem value="development">Development</MenuItem>
                <MenuItem value="staging">Staging</MenuItem>
                <MenuItem value="production">Production</MenuItem>
              </Select>
            </FormControl>
          </>
        );

      case 4: // Flow Definition
        return (
          <>
            <TextField
              fullWidth
              label="Flow Name"
              value={formData.name || ''}
              onChange={(e) => handleChange('name', e.target.value)}
              margin="normal"
              placeholder="e.g., Age Verification Flow"
            />
            <FormControl fullWidth margin="normal">
              <InputLabel>Flow Type</InputLabel>
              <Select
                value={formData.flowType || ''}
                label="Flow Type"
                onChange={(e) => handleChange('flowType', e.target.value)}
              >
                <MenuItem value="verification">Verification (Check credentials)</MenuItem>
                <MenuItem value="issuance">Issuance (Issue credentials)</MenuItem>
                <MenuItem value="combined">Combined (Verify & Issue)</MenuItem>
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
        Quick Create (Basic Configuration)
      </Typography>
      {renderFields()}
    </Box>
  );
}

export default GuidedSetupWizard;
