/**
 * Application Form Component
 *
 * Dynamic multi-step wizard for applicants to apply for credentials.
 * Dynamically renders fields based on credential configuration's
 * required_fields, optional_fields, and custom_fields.
 */

import { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Container,
  Paper,
  Typography,
  Button,
  Stepper,
  Step,
  StepLabel,
  Grid,
  Card,
  CardContent,
  Alert,
  CircularProgress,
  Checkbox,
  FormControlLabel,
  Chip,
  Fade,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useAuth } from '../../hooks/useAuth';
import { usePreview } from '../../contexts/PreviewContext';
import { DynamicFieldGroup } from './DynamicFieldRenderer';


const API_URL = import.meta.env.VITE_API_URL || '';

function normalizeCredentialConfigInput(config) {
  if (!config) {
    return null;
  }

  const requiredFields = Array.isArray(config.required_fields)
    ? config.required_fields
    : (Array.isArray(config.requiredFields) ? config.requiredFields : []);
  const optionalFields = Array.isArray(config.optional_fields)
    ? config.optional_fields
    : (Array.isArray(config.optionalFields) ? config.optionalFields : []);
  const customFields = Array.isArray(config.custom_fields)
    ? config.custom_fields
    : (Array.isArray(config.customFields) ? config.customFields : []);

  return {
    ...config,
    id: config.id,
    credential_type: config.credential_type || config.credentialType,
    display_name: config.display_name || config.name,
    required_fields: requiredFields,
    optional_fields: optionalFields,
    custom_fields: customFields,
    field_validation_rules: config.field_validation_rules || {},
  };
}

/**
 * Group fields into logical steps based on their names/prefixes
 */
function groupFieldsIntoSteps(requiredFields = [], optionalFields = [], customFields = [], t) {
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
  
  if (personal.length > 0) steps.push({ label: t('applicationForm.steps.personalInfo'), fields: personal });
  if (address.length > 0) steps.push({ label: t('applicationForm.steps.address'), fields: address });
  if (document.length > 0) steps.push({ label: t('applicationForm.steps.documentDetails'), fields: document });
  if (other.length > 0) steps.push({ label: t('applicationForm.steps.additionalInfo'), fields: other });
  if (photo.length > 0) steps.push({ label: t('applicationForm.steps.photos'), fields: photo });
  steps.push({ label: t('applicationForm.steps.review'), fields: [] });
  
  return steps;
}

export default function ApplicationForm() {
  const { t } = useTranslation('applicant');
  const { credentialType: credentialConfigId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, organizationId } = useAuth();
  const { isPreview } = usePreview?.() || { isPreview: false };
  const fileInputRefs = useRef({});

  const [activeStep, setActiveStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [submitted, setSubmitted] = useState(false);
  const [applicationId, setApplicationId] = useState(null);
  const [credentialConfig, setCredentialConfig] = useState(
    normalizeCredentialConfigInput(location.state?.credential) || null
  );
  const [configLoading, setConfigLoading] = useState(false);

  // Dynamic form data (keys based on credential config)
  const [formData, setFormData] = useState({
    acceptTerms: false,
  });

  // Validation errors
  const [validationErrors, setValidationErrors] = useState({});

  const normalizeTemplateToFormConfig = (template) => {
    const claims = Array.isArray(template?.claims) ? template.claims : [];
    const requiredClaims = claims.filter((claim) => claim?.required).map((claim) => claim?.name).filter(Boolean);
    const optionalClaims = claims.filter((claim) => !claim?.required).map((claim) => claim?.name).filter(Boolean);

    return {
      id: template?.id,
      credentialType: template?.credential_type,
      credential_type: template?.credential_type,
      name: template?.name,
      display_name: template?.name,
      description: template?.description,
      required_fields: requiredClaims,
      optional_fields: optionalClaims,
      custom_fields: [],
      field_validation_rules: {},
      submission_instructions: null,
      validity_rules: template?.validity_rules || null,
      claims,
    };
  };
  
  // Compute steps dynamically from credential config
  const steps = useMemo(() => {
    if (!credentialConfig) return [{ label: t('applicationForm.steps.review'), fields: [] }];
    
    return groupFieldsIntoSteps(
      credentialConfig.required_fields || [],
      credentialConfig.optional_fields || [],
      credentialConfig.custom_fields || [],
      t
    );
  }, [credentialConfig, t]);
  
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

    const response = await fetch(`${API_URL}/v1/applicants/profiles/${applicantId}`, {
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

    const response = await fetch(`${API_URL}/v1/applicants/by-user/${user.user_id}`, {
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

    const response = await fetch(`${API_URL}/v1/applicants`, {
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
          `${API_URL}/v1/credential-templates/${credentialConfigId}`,
          { credentials: 'include' }
        );
        if (!response.ok) {
          throw new Error('Unable to load credential configuration');
        }
        const data = await response.json();
        setCredentialConfig(normalizeTemplateToFormConfig(data));
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
        organization_id: organizationId,
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
        const updateResponse = await fetch(`${API_URL}/v1/applicants/profiles/${applicantId}`, {
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

      const createResponse = await fetch(`${API_URL}/v1/applicants/applications`, {
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
        `${API_URL}/v1/applicants/applications/${created.id}/submit`,
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
          `${API_URL}/v1/applicants/profiles/${applicantId}/biometrics`,
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
          {credentialConfig?.submission_instructions || t('applicationForm.instructions.default')}
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
        {t('applicationForm.review.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        {t('applicationForm.review.description')}
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
                      displayValue = value?.name || t('applicationForm.review.uploaded');
                    } else if (field.type === 'address') {
                      displayValue = value ? `${value.street}, ${value.city}, ${value.state} ${value.zip}` : '';
                    } else if (field.type === 'boolean') {
                      displayValue = value ? t('common.yes', { ns: 'common' }) : t('common.no', { ns: 'common' });
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
            label={t('applicationForm.review.terms')}
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
          {isPreview ? t('applicationForm.success.previewTitle') : t('applicationForm.success.title')}
        </Typography>
        {isPreview ? (
          <>
            <Alert severity="info" sx={{ maxWidth: 600, mx: 'auto', mb: 3, textAlign: 'left' }}>
              <Typography variant="body2" paragraph>
                <strong>{t('applicationForm.success.previewMode')}:</strong> {t('applicationForm.success.previewMessage')}
              </Typography>
              <Typography variant="body2">
                {t('applicationForm.success.previewNote')}
              </Typography>
            </Alert>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
              {t('applicationForm.success.dataCollected')}
            </Typography>
            <Box component="pre" sx={{ textAlign: 'left', bgcolor: 'grey.100', p: 2, borderRadius: 1, fontSize: '0.85rem', overflow: 'auto', maxHeight: 300, maxWidth: 600, mx: 'auto' }}>
              {JSON.stringify(formData, null, 2)}
            </Box>
          </>
        ) : (
          <>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
              {t('applicationForm.success.message')}
            </Typography>
            
            {applicationId && (
              <Chip
                label={t('applicationForm.success.applicationId', { id: applicationId })}
                color="primary"
                variant="outlined"
                sx={{ mb: 3 }}
                data-testid="application-id"
                data-value={applicationId}
              />
            )}

            <Alert severity="info" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}>
              {t('applicationForm.success.nextSteps')}
            </Alert>

            <Button
              variant="contained"
              onClick={() => navigate('/applicant/applications')}
            >
              {t('applicationForm.success.viewApplications')}
            </Button>
          </>
        )}
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
          <Typography sx={{ mt: 2 }}>{t('applicationForm.loadingConfig')}</Typography>
        </Paper>
      </Container>
    );
  }

  if (!credentialConfig && !credentialConfigId) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4 }}>
          <Alert severity="warning" sx={{ mb: 2 }}>
            {t('applicationForm.errors.noCredential')}
          </Alert>
          <Button variant="contained" onClick={() => navigate('/console/applicant/catalog')}>
            {t('applicationForm.actions.gotoCatalog')}
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
            {credentialConfig?.display_name || t('applicationForm.title.default')}
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary">
          {t('applicationForm.description')}
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
            {t('applicationForm.navigation.back')}
          </Button>

          {activeStep < steps.length - 1 ? (
            <Button
              variant="contained"
              onClick={handleNext}
              endIcon={<ArrowForwardIcon />}
              data-testid="next-step-btn"
            >
              {t('applicationForm.navigation.next')}
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
              {submitting
                ? (isPreview ? t('applicationForm.navigation.simulating') : t('applicationForm.navigation.submitting'))
                : (isPreview ? t('applicationForm.navigation.previewSubmit') : t('applicationForm.navigation.submit'))}
            </Button>
          )}
        </Box>
      </Paper>
    </Container>
  );
}
