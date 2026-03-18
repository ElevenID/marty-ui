import { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  Step,
  StepContent,
  StepLabel,
  Stepper,
  TextField,
  Typography,
} from '@mui/material';
import { createApplicant, enrollBiometric } from '../../services/applicantApi';
import {
  APPLICANT_REGISTRATION_STEPS,
  canCompleteBiometricEnrollment,
  canContinueApplicantRegistration,
  completeApplicantBiometricEnrollment,
  createApplicantRegistrationFormData,
  registerApplicant,
  resolveBiometricCaptured,
  updateApplicantRegistrationFormData,
} from '../../application/vetting';
import { BiometricCapture } from './BiometricCapture';
import { NATIONALITIES } from './shared';

/**
 * Component for new applicant registration with biometric enrollment.
 */
export function ApplicantRegistration({ userId, onComplete, onCancel }) {
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [formData, setFormData] = useState(() => createApplicantRegistrationFormData());
  const [createdApplicant, setCreatedApplicant] = useState(null);
  const [biometricData, setBiometricData] = useState(null);

  const handleFormChange = (field, value) => {
    setFormData((prev) => updateApplicantRegistrationFormData(prev, field, value));
  };

  const handleCreateApplicant = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await registerApplicant({ createApplicant, userId, formData });
      setCreatedApplicant(result.createdApplicant);
      setActiveStep(result.activeStep);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBiometricCapture = (data) => {
    const result = resolveBiometricCaptured(data);
    setBiometricData(result.biometricData);
  };

  const handleEnrollBiometric = async () => {
    if (!canCompleteBiometricEnrollment({ createdApplicant, biometricData })) return;

    setLoading(true);
    setError(null);
    try {
      const result = await completeApplicantBiometricEnrollment({
        enrollBiometric,
        createdApplicant,
        biometricData,
      });
      if (!result) return;
      setActiveStep(result.activeStep);
      onComplete?.(result.completedApplicant);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 600, mx: 'auto' }}>
      <Typography variant="h5" gutterBottom>
        Applicant Registration
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Stepper activeStep={activeStep} orientation="vertical">
        <Step>
          <StepLabel>{APPLICANT_REGISTRATION_STEPS[0].label}</StepLabel>
          <StepContent>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              {APPLICANT_REGISTRATION_STEPS[0].description}
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  required
                  label="Given Name"
                  value={formData.given_name}
                  onChange={(e) => handleFormChange('given_name', e.target.value)}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  required
                  label="Family Name"
                  value={formData.family_name}
                  onChange={(e) => handleFormChange('family_name', e.target.value)}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  required
                  type="email"
                  label="Email"
                  value={formData.email}
                  onChange={(e) => handleFormChange('email', e.target.value)}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  type="tel"
                  label="Phone Number"
                  value={formData.phone_number}
                  onChange={(e) => handleFormChange('phone_number', e.target.value)}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  required
                  type="date"
                  label="Date of Birth"
                  InputLabelProps={{ shrink: true }}
                  value={formData.date_of_birth}
                  onChange={(e) => handleFormChange('date_of_birth', e.target.value)}
                />
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth required>
                  <InputLabel>Nationality</InputLabel>
                  <Select
                    value={formData.nationality}
                    label="Nationality"
                    onChange={(e) => handleFormChange('nationality', e.target.value)}
                  >
                    {NATIONALITIES.map((nationality) => (
                      <MenuItem key={nationality.code} value={nationality.code}>{nationality.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Address</Typography>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Street Address"
                  value={formData.address.street_line1}
                  onChange={(e) => handleFormChange('address.street_line1', e.target.value)}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="City"
                  value={formData.address.city}
                  onChange={(e) => handleFormChange('address.city', e.target.value)}
                />
              </Grid>
              <Grid item xs={3}>
                <TextField
                  fullWidth
                  label="State"
                  value={formData.address.state_province}
                  onChange={(e) => handleFormChange('address.state_province', e.target.value)}
                />
              </Grid>
              <Grid item xs={3}>
                <TextField
                  fullWidth
                  label="Postal Code"
                  value={formData.address.postal_code}
                  onChange={(e) => handleFormChange('address.postal_code', e.target.value)}
                />
              </Grid>
            </Grid>

            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button onClick={onCancel}>Cancel</Button>
              <Button
                variant="contained"
                onClick={handleCreateApplicant}
                disabled={loading || !canContinueApplicantRegistration(formData)}
              >
                {loading ? <CircularProgress size={24} /> : 'Continue'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        <Step>
          <StepLabel>{APPLICANT_REGISTRATION_STEPS[1].label}</StepLabel>
          <StepContent>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Please capture your facial biometric for identity verification.
            </Typography>

            <BiometricCapture
              biometricType="FACIAL"
              onCapture={handleBiometricCapture}
              disabled={loading}
            />

            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button onClick={() => setActiveStep(0)}>Back</Button>
              <Button
                variant="contained"
                onClick={handleEnrollBiometric}
                disabled={loading || !biometricData}
              >
                {loading ? <CircularProgress size={24} /> : 'Complete Registration'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        <Step>
          <StepLabel>{APPLICANT_REGISTRATION_STEPS[2].label}</StepLabel>
          <StepContent>
            <Alert severity="success" sx={{ mb: 2 }}>
              Registration complete! You can now submit applications for travel documents.
            </Alert>
            <Button variant="contained" onClick={() => onComplete?.(createdApplicant)}>
              Continue to Applications
            </Button>
          </StepContent>
        </Step>
      </Stepper>
    </Box>
  );
}
