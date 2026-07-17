/**
 * Credential Offer Generation Dialog
 * 
 * Modal dialog for manually generating OID4VCI credential offers.
 * Features:
 * - Applicant selector
 * - Credential template picker
 * - Preview of claims to issue
 * - Expiry time selector
 * - Generated QR code display
 */

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Stepper,
  Step,
  StepLabel,
  Box,
  TextField,
  Autocomplete,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Alert,
  CircularProgress,
  Chip,
  Stack,
  Paper,
  Divider,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import SendIcon from '@mui/icons-material/Send';
import QRCodeDisplay from './QRCodeDisplay';

const STEPS = ['Select Recipient', 'Choose Credential', 'Review & Generate'];

const EXPIRY_OPTIONS = [
  { value: 5, label: '5 minutes', seconds: 300 },
  { value: 15, label: '15 minutes', seconds: 900 },
  { value: 60, label: '1 hour', seconds: 3600 },
  { value: 1440, label: '24 hours', seconds: 86400 },
];

const CredentialOfferDialog = ({
  open,
  onClose,
  applicants = [],
  credentialTemplates = [],
  onGenerateOffer,
  flowContext = null,  // Pre-populated from flow if available
}) => {
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Form state
  const [selectedApplicant, setSelectedApplicant] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [expiryMinutes, setExpiryMinutes] = useState(15);
  const [credentialData, setCredentialData] = useState({});
  
  // Generated offer
  const [generatedOffer, setGeneratedOffer] = useState(null);

  // Reset state when dialog opens/closes
  useEffect(() => {
    if (open) {
      // Pre-populate from flow context if available
      if (flowContext?.applicantId) {
        const applicant = applicants.find(a => a.id === flowContext.applicantId);
        if (applicant) setSelectedApplicant(applicant);
      }
      if (flowContext?.templateId) {
        const template = credentialTemplates.find(t => t.id === flowContext.templateId);
        if (template) setSelectedTemplate(template);
      }
      setActiveStep(0);
      setGeneratedOffer(null);
      setError(null);
    }
  }, [open, flowContext, applicants, credentialTemplates]);

  // Update credential data when template changes
  useEffect(() => {
    if (selectedTemplate && selectedApplicant) {
      // Build default credential data from template claims
      const defaultData = {};
      if (selectedTemplate.claims) {
        selectedTemplate.claims.forEach(claim => {
          // Try to map from applicant data if available
          if (selectedApplicant[claim.name]) {
            defaultData[claim.name] = selectedApplicant[claim.name];
          } else {
            // Set default value based on claim type
            defaultData[claim.name] = claim.default_value || '';
          }
        });
      }
      setCredentialData(defaultData);
    }
  }, [selectedTemplate, selectedApplicant]);

  const handleNext = () => {
    setActiveStep((prev) => prev + 1);
    setError(null);
  };

  const handleBack = () => {
    setActiveStep((prev) => prev - 1);
    setError(null);
  };

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);

    try {
      const offer = await onGenerateOffer({
        applicantId: selectedApplicant.id,
        templateId: selectedTemplate.id,
        credentialData,
        expiryMinutes,
      });

      setGeneratedOffer(offer);
      handleNext(); // Move to final step showing QR
    } catch (err) {
      console.error('Failed to generate offer:', err);
      setError(err.message || 'Failed to generate credential offer');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setActiveStep(0);
    setGeneratedOffer(null);
    setError(null);
    onClose();
  };

  // Validate current step
  const isStepValid = () => {
    switch (activeStep) {
      case 0:
        return selectedApplicant !== null;
      case 1:
        return selectedTemplate !== null;
      case 2:
        return true;
      default:
        return false;
    }
  };

  // Render step content
  const renderStepContent = () => {
    switch (activeStep) {
      case 0:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Select the person who will receive this credential
            </Typography>
            <Autocomplete
              value={selectedApplicant}
              onChange={(_, value) => setSelectedApplicant(value)}
              options={applicants}
              getOptionLabel={(option) => 
                `${option.firstName || ''} ${option.lastName || ''} (${option.email || option.id})`
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Recipient"
                  placeholder="Search by name or email"
                  required
                />
              )}
              fullWidth
            />

            {selectedApplicant && (
              <Paper sx={{ mt: 2, p: 2, bgcolor: 'grey.50' }}>
                <Typography variant="caption" color="text.secondary">
                  Selected Recipient
                </Typography>
                <Typography variant="body2" fontWeight="medium">
                  {selectedApplicant.firstName} {selectedApplicant.lastName}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {selectedApplicant.email}
                </Typography>
              </Paper>
            )}
          </Box>
        );

      case 1:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Choose the credential type to issue
            </Typography>
            <FormControl fullWidth required>
              <InputLabel>Credential Template</InputLabel>
              <Select
                value={selectedTemplate?.id || ''}
                onChange={(e) => {
                  const template = credentialTemplates.find(t => t.id === e.target.value);
                  setSelectedTemplate(template);
                }}
                label="Credential Template"
              >
                {credentialTemplates.map((template) => (
                  <MenuItem key={template.id} value={template.id}>
                    <Box>
                      <Typography variant="body2">{template.name}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {template.description || 'No description'}
                      </Typography>
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            {selectedTemplate && (
              <Paper sx={{ mt: 2, p: 2, bgcolor: 'grey.50' }}>
                <Typography variant="caption" color="text.secondary">
                  Credential Type
                </Typography>
                <Typography variant="body2" fontWeight="medium" gutterBottom>
                  {selectedTemplate.name}
                </Typography>
                <Divider sx={{ my: 1 }} />
                <Typography variant="caption" color="text.secondary">
                  Claims to Issue
                </Typography>
                <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                  {selectedTemplate.claims?.map((claim) => (
                    <Chip
                      key={claim.name}
                      label={claim.name}
                      size="small"
                      variant="outlined"
                    />
                  ))}
                </Stack>
              </Paper>
            )}
          </Box>
        );

      case 2:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Review and configure the credential offer
            </Typography>

            {/* Expiry Time Selector */}
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>QR Code Expiry</InputLabel>
              <Select
                value={expiryMinutes}
                onChange={(e) => setExpiryMinutes(e.target.value)}
                label="QR Code Expiry"
              >
                {EXPIRY_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            {/* Credential Data Preview */}
            <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
              <Typography variant="caption" color="text.secondary" gutterBottom>
                Credential Claims Preview
              </Typography>
              <Stack spacing={1} sx={{ mt: 1 }}>
                {Object.entries(credentialData).map(([key, value]) => (
                  <Box key={key}>
                    <Typography variant="caption" color="text.secondary">
                      {key}
                    </Typography>
                    <Typography variant="body2" fontWeight="medium">
                      {String(value) || '(empty)'}
                    </Typography>
                  </Box>
                ))}
              </Stack>
            </Paper>
          </Box>
        );

      case 3:
        // QR Code Display - after generation
        return (
          <Box sx={{ mt: 2 }}>
            {generatedOffer && (
              <>
                <QRCodeDisplay
                  offerUri={generatedOffer.credential_offer_uri}
                  qrPayload={generatedOffer.qr_code_data}
                  expiresAt={generatedOffer.expires_at}
                  createdAt={new Date().toISOString()}
                  title="Credential Offer Generated"
                  instructions="Share this QR code with the recipient. They can scan it with their digital wallet to receive the credential."
                  onRefresh={handleGenerate}
                  showDeepLink={true}
                  showCopyLink={true}
                  branding={generatedOffer.branding}
                />
                
                {/* Additional sharing options for deep link */}
                <Paper sx={{ p: 2, mt: 2, bgcolor: 'grey.50' }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Alternative Delivery Methods
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    If the recipient is on a mobile device, you can share the deep link directly via messaging apps, email, or SMS.
                  </Typography>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    <Chip
                      label="Copy Deep Link"
                      size="small"
                      onClick={() => {
                        navigator.clipboard.writeText(generatedOffer.credential_offer_uri);
                      }}
                    />
                    {generatedOffer.offer_endpoint && (
                      <Chip
                        label="Copy HTTP URL"
                        size="small"
                        variant="outlined"
                        onClick={() => {
                          navigator.clipboard.writeText(generatedOffer.offer_endpoint);
                        }}
                      />
                    )}
                  </Stack>
                </Paper>
              </>
            )}

            <Alert severity="success" sx={{ mt: 2 }}>
              Credential offer generated successfully! The recipient can now scan the QR code with their wallet or use the deep link on mobile.
            </Alert>
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: { minHeight: '500px' }
      }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">Generate Credential Offer</Typography>
          <Button
            onClick={handleClose}
            size="small"
            startIcon={<CloseIcon />}
          >
            Close
          </Button>
        </Box>
      </DialogTitle>

      <DialogContent>
        {/* Stepper */}
        <Stepper activeStep={activeStep} sx={{ mb: 3 }}>
          {STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Step Content */}
        {renderStepContent()}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        {activeStep === 0 ? (
          <Button onClick={handleClose}>Cancel</Button>
        ) : activeStep < 3 ? (
          <Button onClick={handleBack} startIcon={<NavigateBeforeIcon />}>
            Back
          </Button>
        ) : null}

        {activeStep < 2 ? (
          <Button
            variant="contained"
            onClick={handleNext}
            endIcon={<NavigateNextIcon />}
            disabled={!isStepValid()}
          >
            Next
          </Button>
        ) : activeStep === 2 ? (
          <Button
            variant="contained"
            onClick={handleGenerate}
            startIcon={loading ? <CircularProgress size={16} /> : <SendIcon />}
            disabled={loading}
          >
            {loading ? 'Generating...' : 'Generate QR Code'}
          </Button>
        ) : (
          <Button variant="contained" onClick={handleClose}>
            Done
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default CredentialOfferDialog;
