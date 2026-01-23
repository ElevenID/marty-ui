/**
 * Application Form Component
 *
 * Dynamic multi-step wizard for applicants to apply for credentials.
 * Dynamically renders fields based on credential configuration's
 * required_fields, optional_fields, and custom_fields.
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Container,
  Paper,
  Typography,
  Button,
  Stepper,
  Step,
  StepLabel,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Card,
  CardContent,
  Alert,
  CircularProgress,
  Checkbox,
  FormControlLabel,
  Chip,
  Avatar,
  Fade,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import PhotoCameraIcon from '@mui/icons-material/PhotoCamera';
import DeleteIcon from '@mui/icons-material/Delete';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import { useAuth } from '../../hooks/useAuth';
import { DynamicFieldRenderer, DynamicFieldGroup } from './DynamicFieldRenderer';


const API_URL = process.env.REACT_APP_API_URL || '';

/**
 * Group fields into logical steps based on their names/prefixes
 */
function groupFieldsIntoSteps(requiredFields = [], optionalFields = [], customFields = []) {
  const steps = [];
  
  // Define standard field categories
  const personalFields = ['first_name', 'last_name', 'family_name', 'given_name', 'date_of_birth', 'birth_date', 'email', 'phone', 'nationality', 'sex', 'gender'];
  const addressFields = ['street', 'city', 'state', 'zip', 'postal_code', 'country', 'address'];
  const documentFields = ['document_number', 'license_class', 'driving_privileges', 'restrictions', 'issue_date', 'expiry_date'];
  const photoFields = ['portrait', 'signature', 'photo'];
  
  const allFields = [
    ...requiredFields.map(f => ({ name: typeof f === 'string' ? f : f.name, required: true, ...f })),
    ...optionalFields.map(f => ({ name: typeof f === 'string' ? f : f.name, required: false, ...f })),
    ...customFields.map(f => ({ name: f.name, required: false, ...f })),
  ];
  
  // Categorize fields
  const personal = allFields.filter(f => personalFields.some(pf => f.name.toLowerCase().includes(pf)));
  const address = allFields.filter(f => addressFields.some(af => f.name.toLowerCase().includes(af)));
  const document = allFields.filter(f => documentFields.some(df => f.name.toLowerCase().includes(df)));
  const photo = allFields.filter(f => photoFields.some(pf => f.name.toLowerCase().includes(pf)));
  const other = allFields.filter(f => 
    !personal.includes(f) && 
    !address.includes(f) && 
    !document.includes(f) && 
    !photo.includes(f)
  );
  
  if (personal.length > 0) steps.push({ label: 'Personal Information', fields: personal });
  if (address.length > 0) steps.push({ label: 'Address', fields: address });
  if (document.length > 0) steps.push({ label: 'Document Details', fields: document });
  if (other.length > 0) steps.push({ label: 'Additional Information', fields: other });
  if (photo.length > 0) steps.push({ label: 'Photos & Documents', fields: photo });
  steps.push({ label: 'Review & Submit', fields: [] });
  
  return steps;
}

export default function ApplicationForm() {
  const { credentialType: credentialConfigId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, organizationId } = useAuth();
  const fileInputRefs = useRef({});

  const [activeStep, setActiveStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [submitted, setSubmitted] = useState(false);
  const [applicationId, setApplicationId] = useState(null);
  const [credentialConfig, setCredentialConfig] = useState(
    location.state?.credential || null
  );
  const [configLoading, setConfigLoading] = useState(false);

  // Dynamic form data (keys based on credential config)
  const [formData, setFormData] = useState({
    acceptTerms: false,
  });

  // Validation errors
  const [validationErrors, setValidationErrors] = useState({});
  
  // Compute steps dynamically from credential config
  const steps = useMemo(() => {
    if (!credentialConfig) return [{ label: 'Review & Submit', fields: [] }];
    
    return groupFieldsIntoSteps(
      credentialConfig.required_fields || [],
      credentialConfig.optional_fields || [],
      credentialConfig.custom_fields || []
    );
  }, [credentialConfig]);
  
  // Flatten all fields for validation
  const allFields = useMemo(() => {
    return steps.slice(0, -1).flatMap(step => step.fields);
  }, [steps]);
  
  const requiredFieldNames = useMemo(() => {
    return allFields.filter(f => f.required).map(f => f.name);
  }, [allFields]);

  const fetchApplicantById = async (applicantId) => {
    if (!applicantId) {
      return null;
    }

    const response = await fetch(`${API_URL}/api/applicants/${applicantId}`, {
      credentials: 'include',
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return data?.id || null;
  };

  const fetchApplicantByUser = async () => {
    if (!user?.user_id) {
      return null;
    }

    const response = await fetch(`${API_URL}/api/applicants/by-user/${user.user_id}`, {
      credentials: 'include',
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return data?.id || null;
  };

  const resolveApplicantId = async () => {
    const byId = await fetchApplicantById(user?.applicant_id);
    if (byId) {
      return byId;
    }

    const byUser = await fetchApplicantByUser();
    return byUser || null;
  };

  const createApplicant = async (applicantData) => {
    if (!user?.user_id) {
      throw new Error('Unable to resolve applicant profile');
    }

    const response = await fetch(`${API_URL}/api/applicants`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(applicantData),
    });

    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.detail || 'Failed to create applicant');
    }

    const data = await response.json();
    return data?.id || null;
  };

  const readFileAsBase64 = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result;
        if (typeof result !== 'string') {
          resolve(null);
          return;
        }
        const [, base64] = result.split(',');
        resolve(base64 || null);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });

  useEffect(() => {
    const fetchCredentialConfig = async () => {
      if (!credentialConfigId || credentialConfig) {
        return;
      }
      if (!organizationId) {
        setError('Organization context missing for credential configuration.');
        return;
      }
      setConfigLoading(true);
      try {
        const response = await fetch(
          `${API_URL}/api/organizations/${organizationId}/credential-types/${credentialConfigId}`,
          { credentials: 'include' }
        );
        if (!response.ok) {
          throw new Error('Unable to load credential configuration');
        }
        const data = await response.json();
        setCredentialConfig(data.credential_type || null);
      } catch (err) {
        setError(err.message);
      } finally {
        setConfigLoading(false);
      }
    };

    fetchCredentialConfig();
  }, [credentialConfigId, credentialConfig, organizationId]);

  useEffect(() => {
    // Pre-fill user email if email field exists
    if (user?.email && allFields.some(f => f.name === 'email')) {
      setFormData(prev => ({ ...prev, email: user.email }));
    }
  }, [user, allFields]);

  const handleFieldChange = (fieldName, value) => {
    setFormData(prev => ({
      ...prev,
      [fieldName]: value
    }));
    // Clear validation error when field is edited
    if (validationErrors[fieldName]) {
      setValidationErrors(prev => ({ ...prev, [fieldName]: null }));
    }
  };

  const validateStep = (stepIndex) => {
    const errors = {};
    
    // Last step is review - just check terms
    if (stepIndex === steps.length - 1) {
      if (!formData.acceptTerms) {
        errors.acceptTerms = 'You must accept the terms';
      }
      setValidationErrors(errors);
      return Object.keys(errors).length === 0;
    }
    
    // Validate fields in current step
    const currentStepFields = steps[stepIndex]?.fields || [];
    const validationRules = credentialConfig?.field_validation_rules || {};
    
    currentStepFields.forEach(field => {
      const fieldName = field.name;
      const value = formData[fieldName];
      const rules = validationRules[fieldName];
      
      // Check required
      if (field.required && !value) {
        errors[fieldName] = `${field.label || fieldName.replace(/_/g, ' ')} is required`;
        return;
      }
      
      // Skip validation if field is empty and not required
      if (!value && !field.required) return;
      
      // Apply validation rules
      if (rules) {
        if (rules.min_length && value.length < rules.min_length) {
          errors[fieldName] = `Minimum length is ${rules.min_length}`;
        }
        if (rules.max_length && value.length > rules.max_length) {
          errors[fieldName] = `Maximum length is ${rules.max_length}`;
        }
        if (rules.pattern && !new RegExp(rules.pattern).test(value)) {
          errors[fieldName] = rules.pattern_description || 'Invalid format';
        }
        if (rules.min_value !== undefined && value < rules.min_value) {
          errors[fieldName] = `Minimum value is ${rules.min_value}`;
        }
        if (rules.max_value !== undefined && value > rules.max_value) {
          errors[fieldName] = `Maximum value is ${rules.max_value}`;
        }
      }
    });
    
    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleNext = () => {
    if (validateStep(activeStep)) {
      setActiveStep(prev => prev + 1);
    }
  };

  const handleBack = () => {
    setActiveStep(prev => prev - 1);
  };

  const handleSubmit = async () => {
    if (!validateStep(activeStep)) return;

    setSubmitting(true);
    setError(null);

    try {
      if (!credentialConfig?.id && !credentialConfigId) {
        throw new Error('Please select a credential to apply for.');
      }
      
      // Build applicant data from form
      const applicantData = {
        user_id: user.user_id,
        given_name: formData.given_name || formData.first_name || '',
        family_name: formData.family_name || formData.last_name || '',
        email: formData.email || user.email,
        date_of_birth: formData.date_of_birth || formData.birth_date,
        nationality: formData.nationality || 'USA',
      };
      
      // Build address from form (if address fields exist)
      const address = {};
      if (formData.street) address.street_line1 = formData.street;
      if (formData.city) address.city = formData.city;
      if (formData.state) address.state_province = formData.state;
      if (formData.zip || formData.postal_code) address.postal_code = formData.zip || formData.postal_code;
      if (formData.country) address.country = formData.country;
      else address.country = 'USA';
      
      if (Object.keys(address).length > 0) {
        applicantData.address = address;
      }

      let applicantId = await resolveApplicantId();
      let applicantCreated = false;

      if (!applicantId) {
        applicantId = await createApplicant(applicantData);
        applicantCreated = true;
      }

      if (!applicantId) {
        throw new Error('Unable to resolve applicant profile');
      }

      if (!applicantCreated) {
        const updateResponse = await fetch(`${API_URL}/api/applicants/${applicantId}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(applicantData),
        });

        if (!updateResponse.ok) {
          if (updateResponse.status === 404) {
            const fallbackApplicantId = await fetchApplicantByUser();
            if (fallbackApplicantId) {
              applicantId = fallbackApplicantId;
            } else {
              applicantId = await createApplicant(applicantData);
              applicantCreated = true;
            }
            if (!applicantId) {
              throw new Error('Unable to resolve applicant profile');
            }
          } else {
            const data = await updateResponse.json();
            throw new Error(data.detail || 'Failed to update applicant');
          }
        }
      }

      const createResponse = await fetch(`${API_URL}/api/applicants/applications`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          applicant_id: applicantId,
          credential_configuration_id: credentialConfig?.id || credentialConfigId,
          issuing_authority: 'Marty Trust Services',
          requested_validity_years: 10,
          metadata: {
            document_number: formData.documentNumber,
            credential_type: credentialConfig?.credentialType || credentialConfig?.credential_type,
            credential_display_name: credentialConfig?.name || credentialConfig?.display_name,
            license_class: formData.licenseClass,
            restrictions: formData.restrictions,
          },
        }),
      });

      if (!createResponse.ok) {
        const data = await createResponse.json();
        throw new Error(data.detail || 'Failed to create application');
      }

      const created = await createResponse.json();

      const submitResponse = await fetch(
        `${API_URL}/api/applicants/applications/${created.id}/submit`,
        {
          method: 'POST',
          credentials: 'include',
        }
      );

      if (!submitResponse.ok) {
        const data = await submitResponse.json();
        throw new Error(data.detail || 'Failed to submit application');
      }

      const submittedApplication = await submitResponse.json();

      // Upload portrait if present
      const portraitField = allFields.find(f => f.name === 'portrait' || f.type === 'file');
      if (portraitField && formData[portraitField.name]) {
        const imageBase64 = await readFileAsBase64(formData[portraitField.name]);
        const templateBase64 = imageBase64 || btoa('test-biometric-template');

        const biometricResponse = await fetch(
          `${API_URL}/api/applicants/${applicantId}/biometrics`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              biometric_type: 'FACIAL',
              template_data_base64: templateBase64,
              image_data_base64: imageBase64,
              is_live_capture: true,
              capture_device_id: 'web-form',
            }),
          }
        );

        if (!biometricResponse.ok) {
          const data = await biometricResponse.json();
          throw new Error(data.detail || 'Failed to enroll biometric');
        }
      }

      setApplicationId(submittedApplication.id);
      setSubmitted(true);

      // Redirect after delay
      setTimeout(() => {
        navigate('/my-applications');
      }, 5000);
    } catch (err) {
      console.error('Error submitting application:', err);
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Render a dynamic step based on fields
  const renderDynamicStep = (stepIndex) => {
    const step = steps[stepIndex];
    if (!step) return null;

    return (
      <Box data-testid={`step-${stepIndex}`}>
        <Typography variant="h6" gutterBottom>
          {step.label}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {credentialConfig?.submission_instructions || 'Please fill in all required fields.'}
        </Typography>

        <DynamicFieldGroup
          fields={step.fields}
          values={formData}
          onChange={handleFieldChange}
          errors={validationErrors}
          requiredFields={requiredFieldNames}
          validationRules={credentialConfig?.field_validation_rules}
          fileInputRefs={fileInputRefs.current}
        />
      </Box>
    );
  };

  const renderReviewStep = () => (
    <Box data-testid="review-step">
      <Typography variant="h6" gutterBottom>
        Review Your Application
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Please review your information before submitting.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          {steps.slice(0, -1).map((step, idx) => (
            <Card key={idx} variant="outlined" sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  {step.label}
                </Typography>
                <Grid container spacing={2}>
                  {step.fields.map((field) => {
                    const fieldName = field.name;
                    const value = formData[fieldName];
                    
                    // Skip empty optional fields
                    if (!value && !field.required) return null;
                    
                    // Format value for display
                    let displayValue = value;
                    if (field.type === 'file') {
                      displayValue = value?.name || 'Uploaded';
                    } else if (field.type === 'address') {
                      displayValue = value ? `${value.street}, ${value.city}, ${value.state} ${value.zip}` : '';
                    } else if (field.type === 'boolean') {
                      displayValue = value ? 'Yes' : 'No';
                    }
                    
                    return (
                      <Grid item xs={12} sm={6} key={fieldName}>
                        <Typography variant="body2" color="text.secondary">
                          {field.label || fieldName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </Typography>
                        <Typography>{displayValue || '-'}</Typography>
                      </Grid>
                    );
                  })}
                </Grid>
              </CardContent>
            </Card>
          ))}
        </Grid>

        <Grid item xs={12}>
          <FormControlLabel
            control={
              <Checkbox
                checked={formData.acceptTerms}
                onChange={(e) => setFormData(prev => ({ ...prev, acceptTerms: e.target.checked }))}
                data-testid="accept-terms-checkbox"
              />
            }
            label="I certify that all information provided is accurate and complete. I understand that providing false information may result in denial of my application."
          />
          {validationErrors.acceptTerms && (
            <Typography color="error" variant="caption" display="block">
              {validationErrors.acceptTerms}
            </Typography>
          )}
        </Grid>
      </Grid>
    </Box>
  );

  const renderSubmittedState = () => (
    <Fade in>
      <Box sx={{ textAlign: 'center', py: 6 }} data-testid="application-submitted">
        <CheckCircleIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
        <Typography variant="h4" gutterBottom>
          Application Submitted!
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          Your application has been submitted successfully.
        </Typography>
        
        {applicationId && (
          <Chip
            label={`Application ID: ${applicationId}`}
            color="primary"
            variant="outlined"
            sx={{ mb: 3 }}
            data-testid="application-id"
            data-value={applicationId}
          />
        )}

        <Alert severity="info" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}>
          You will receive updates on your application status via email. Redirecting to your applications page...
        </Alert>

        <Button
          variant="contained"
          onClick={() => navigate('/my-applications')}
        >
          View My Applications
        </Button>
      </Box>
    </Fade>
  );

  // Use dynamic rendering for all steps
  const getStepContent = (stepIndex) => {
    // Last step is always review
    if (stepIndex === steps.length - 1) {
      return renderReviewStep();
    }
    return renderDynamicStep(stepIndex);
  };

  if (submitted) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4 }}>
          {renderSubmittedState()}
        </Paper>
      </Container>
    );
  }

  if (configLoading) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <CircularProgress />
        </Paper>
      </Container>
    );
  }

  if (!credentialConfig && !credentialConfigId) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4 }}>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Please select a credential from the catalog before starting an application.
          </Alert>
          <Button variant="contained" onClick={() => navigate('/credentials')}>
            Go to Credential Catalog
          </Button>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="md" sx={{ py: 4 }} data-testid="credential-application-form">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
          <CheckCircleIcon color="primary" fontSize="large" />
          <Typography variant="h4" component="h1">
            {credentialConfig?.display_name || 'Credential Application'}
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary">
          Complete the form below to apply for your credential.
        </Typography>
      </Box>

      {/* Stepper */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Stepper activeStep={activeStep} alternativeLabel>
          {steps.map((step, idx) => (
            <Step key={idx}>
              <StepLabel>{step.label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Form Content */}
      <Paper sx={{ p: 4, mb: 3 }}>
        {getStepContent(activeStep)}
      </Paper>

      {/* Navigation */}
      <Paper sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
          <Button
            disabled={activeStep === 0}
            onClick={handleBack}
            startIcon={<ArrowBackIcon />}
          >
            Back
          </Button>

          {activeStep < steps.length - 1 ? (
            <Button
              variant="contained"
              onClick={handleNext}
              endIcon={<ArrowForwardIcon />}
              data-testid="next-step-btn"
            >
              Next
            </Button>
          ) : (
            <Button
              variant="contained"
              color="success"
              onClick={handleSubmit}
              disabled={submitting}
              endIcon={submitting ? <CircularProgress size={20} /> : <CheckCircleIcon />}
              data-testid="submit-application-btn"
            >
              {submitting ? 'Submitting...' : 'Submit Application'}
            </Button>
          )}
        </Box>
      </Paper>
    </Container>
  );
}
