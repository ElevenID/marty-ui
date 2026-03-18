import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControl,
  Grid,
  InputLabel,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Step,
  StepContent,
  StepLabel,
  Stepper,
  TextField,
  Typography,
} from '@mui/material';
import {
  CheckCircle as CheckIcon,
  Schedule as PendingIcon,
} from '@mui/icons-material';
import { useBranding } from '../../hooks/useBranding';
import { createApplication, getDocumentTypes, submitApplication } from '../../services/applicantApi';
import {
  APPLICATION_WIZARD_STEPS,
  canSubmitApplicationWizard,
  createApplicantDocumentApplication,
  createApplicationWizardFormData,
  loadApplicationDocumentTypes,
  resolveDocumentTypeDetails,
  submitApplicantDocumentApplication,
  updateApplicationWizardFormData,
} from '../../application/vetting';
import { DOCUMENT_TYPES } from './shared';

/**
 * Wizard for creating and submitting travel document applications.
 */
export function ApplicationWizard({ applicant, onComplete, onCancel }) {
  const branding = useBranding();
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [documentTypes, setDocumentTypes] = useState([]);
  const [formData, setFormData] = useState(() => createApplicationWizardFormData(branding.issuingAuthority));
  const [createdApplication, setCreatedApplication] = useState(null);

  useEffect(() => {
    const loadDocumentTypes = async () => {
      try {
        const result = await loadApplicationDocumentTypes({ getDocumentTypes });
        setDocumentTypes(result.documentTypes);
      } catch (err) {
        console.error('Failed to load document types:', err);
      }
    };

    loadDocumentTypes();
  }, []);

  const handleFormChange = (field, value) => {
    setFormData((prev) => updateApplicationWizardFormData(prev, field, value));
  };

  const handleCreateApplication = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await createApplicantDocumentApplication({
        createApplication,
        applicantId: applicant.id,
        formData,
      });
      setCreatedApplication(result.createdApplication);
      setActiveStep(result.activeStep);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitApplication = async () => {
    if (!createdApplication) return;

    setLoading(true);
    setError(null);
    try {
      const result = await submitApplicantDocumentApplication({ submitApplication, createdApplication });
      setCreatedApplication(result.createdApplication);
      setActiveStep(result.activeStep);
      onComplete?.(result.completedApplication);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const selectedType = resolveDocumentTypeDetails(documentTypes, formData.document_type);

  return (
    <Box sx={{ maxWidth: 600, mx: 'auto' }}>
      <Typography variant="h5" gutterBottom>
        New Application
      </Typography>

      <Typography variant="body2" color="textSecondary" gutterBottom>
        Applicant: {applicant.full_name}
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Stepper activeStep={activeStep} orientation="vertical">
        <Step>
          <StepLabel>{APPLICATION_WIZARD_STEPS[0].label}</StepLabel>
          <StepContent>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <FormControl fullWidth required>
                  <InputLabel>Document Type</InputLabel>
                  <Select
                    value={formData.document_type}
                    label="Document Type"
                    onChange={(e) => handleFormChange('document_type', e.target.value)}
                  >
                    {DOCUMENT_TYPES.map((documentType) => (
                      <MenuItem key={documentType.value} value={documentType.value}>
                        {documentType.label} - {documentType.description}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {selectedType && (
                <Grid item xs={12}>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <Typography variant="subtitle2">Required Vetting Checks:</Typography>
                    <List dense>
                      {selectedType.requirements?.map((requirement, idx) => (
                        <ListItem key={idx} sx={{ py: 0 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            {requirement.required ? <CheckIcon color="primary" fontSize="small" /> : <PendingIcon fontSize="small" />}
                          </ListItemIcon>
                          <ListItemText
                            primary={requirement.check_type.replace(/_/g, ' ')}
                            secondary={requirement.required ? 'Required' : 'Optional'}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Alert>
                </Grid>
              )}

              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Validity (Years)</InputLabel>
                  <Select
                    value={formData.requested_validity_years}
                    label="Validity (Years)"
                    onChange={(e) => handleFormChange('requested_validity_years', e.target.value)}
                  >
                    <MenuItem value={1}>1 Year</MenuItem>
                    <MenuItem value={5}>5 Years</MenuItem>
                    <MenuItem value={10}>10 Years</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Expedited</InputLabel>
                  <Select
                    value={formData.is_expedited}
                    label="Expedited"
                    onChange={(e) => handleFormChange('is_expedited', e.target.value)}
                  >
                    <MenuItem value={false}>Standard Processing</MenuItem>
                    <MenuItem value={true}>Expedited Processing</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {formData.document_type === 'VISA' && (
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Travel Purpose"
                    value={formData.travel_purpose}
                    onChange={(e) => handleFormChange('travel_purpose', e.target.value)}
                  />
                </Grid>
              )}
            </Grid>

            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button onClick={onCancel}>Cancel</Button>
              <Button
                variant="contained"
                onClick={handleCreateApplication}
                disabled={loading || !canSubmitApplicationWizard(formData)}
              >
                {loading ? <CircularProgress size={24} /> : 'Continue'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        <Step>
          <StepLabel>{APPLICATION_WIZARD_STEPS[1].label}</StepLabel>
          <StepContent>
            <Paper sx={{ p: 2, mb: 2, bgcolor: 'grey.50' }}>
              <Typography variant="h6" gutterBottom>Application Summary</Typography>
              <Grid container spacing={1}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Reference</Typography>
                  <Typography variant="body1">{createdApplication?.reference_number}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Document Type</Typography>
                  <Typography variant="body1">{formData.document_type}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Validity</Typography>
                  <Typography variant="body1">{formData.requested_validity_years} Years</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Processing</Typography>
                  <Typography variant="body1">{formData.is_expedited ? 'Expedited' : 'Standard'}</Typography>
                </Grid>
              </Grid>
            </Paper>

            <Alert severity="warning">
              By submitting this application, you confirm all information is accurate.
              The application will undergo vetting checks which may take several days.
            </Alert>

            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button onClick={() => setActiveStep(0)}>Back</Button>
              <Button
                variant="contained"
                color="primary"
                onClick={handleSubmitApplication}
                disabled={loading}
              >
                {loading ? <CircularProgress size={24} /> : 'Submit Application'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        <Step>
          <StepLabel>{APPLICATION_WIZARD_STEPS[2].label}</StepLabel>
          <StepContent>
            <Alert severity="success" sx={{ mb: 2 }}>
              Your application has been submitted successfully!
            </Alert>
            <Typography variant="body2" sx={{ mb: 2 }}>
              Reference Number: <strong>{createdApplication?.reference_number}</strong>
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Your application is now under review. You will be notified once the vetting
              process is complete. This typically takes 5-10 business days for standard
              processing.
            </Typography>
            <Button variant="contained" onClick={() => onComplete?.(createdApplication)}>
              View Application Status
            </Button>
          </StepContent>
        </Step>
      </Stepper>
    </Box>
  );
}
