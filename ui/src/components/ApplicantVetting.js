/**
 * Applicant Vetting Components
 * 
 * React components for applicant registration, biometric enrollment,
 * application workflow, and vetting dashboard.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Alert,
  Snackbar,
  CircularProgress,
  Tabs,
  Tab,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Divider,
  Tooltip,
  Avatar,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemAvatar,
  LinearProgress,
  Badge,
} from '@mui/material';
import { useBranding } from '../hooks/useBranding';
import {
  Add as AddIcon,
  Person as PersonIcon,
  Visibility as ViewIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
  Schedule as PendingIcon,
  Warning as WarningIcon,
  Assignment as ApplicationIcon,
  CameraAlt as CameraIcon,
  Fingerprint as FingerprintIcon,
  Face as FaceIcon,
  RemoveRedEye as IrisIcon,
  Description as DocumentIcon,
  Security as SecurityIcon,
  History as HistoryIcon,
  Refresh as RefreshIcon,
  Check as PassedIcon,
  Close as FailedIcon,
  Search as SearchIcon,
  PhotoCamera as PhotoCameraIcon,
} from '@mui/icons-material';

// ==================== API Functions ====================

const API_BASE = '/api/applicants';

// Applicant API
export async function createApplicant(data) {
  const response = await fetch(API_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to create applicant');
  }
  return response.json();
}

export async function getApplicant(applicantId) {
  const response = await fetch(`${API_BASE}/${applicantId}`);
  if (!response.ok) throw new Error('Failed to fetch applicant');
  return response.json();
}

export async function getApplicantByUser(userId) {
  const response = await fetch(`${API_BASE}/by-user/${userId}`);
  if (!response.ok && response.status !== 404) throw new Error('Failed to fetch applicant');
  if (response.status === 404) return null;
  return response.json();
}

export async function enrollBiometric(applicantId, data) {
  const response = await fetch(`${API_BASE}/${applicantId}/biometrics`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to enroll biometric');
  }
  return response.json();
}

export async function getApplicantBiometrics(applicantId) {
  const response = await fetch(`${API_BASE}/${applicantId}/biometrics`);
  if (!response.ok) throw new Error('Failed to fetch biometrics');
  return response.json();
}

// Application API
export async function createApplication(data) {
  const response = await fetch(`${API_BASE}/applications`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to create application');
  }
  return response.json();
}

export async function submitApplication(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/submit`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to submit application');
  }
  return response.json();
}

export async function getApplication(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}`);
  if (!response.ok) throw new Error('Failed to fetch application');
  return response.json();
}

export async function listApplications(params = {}) {
  const queryParams = new URLSearchParams();
  if (params.status) queryParams.append('status', params.status);
  if (params.document_type) queryParams.append('document_type', params.document_type);
  if (params.limit) queryParams.append('limit', params.limit);
  if (params.offset) queryParams.append('offset', params.offset);
  
  const response = await fetch(`${API_BASE}/applications?${queryParams}`);
  if (!response.ok) throw new Error('Failed to fetch applications');
  return response.json();
}

export async function getApprovedApplications(limit = 50) {
  const response = await fetch(`${API_BASE}/applications/approved?limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch approved applications');
  return response.json();
}

// Vetting Checks API
export async function getVettingChecks(applicationId) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/checks`);
  if (!response.ok) throw new Error('Failed to fetch vetting checks');
  return response.json();
}

export async function startCheck(checkId) {
  const response = await fetch(`${API_BASE}/checks/${checkId}/start`, {
    method: 'POST',
  });
  if (!response.ok) throw new Error('Failed to start check');
  return response.json();
}

export async function completeCheck(checkId, data) {
  const response = await fetch(`${API_BASE}/checks/${checkId}/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('Failed to complete check');
  return response.json();
}

export async function getPendingChecks(checkType = null) {
  const url = checkType 
    ? `${API_BASE}/checks/pending?check_type=${checkType}` 
    : `${API_BASE}/checks/pending`;
  const response = await fetch(url);
  if (!response.ok) throw new Error('Failed to fetch pending checks');
  return response.json();
}

// Approval API
export async function approveApplication(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to approve application');
  }
  return response.json();
}

export async function rejectApplication(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to reject application');
  }
  return response.json();
}

// KYC API
export async function submitKYC(applicationId, data) {
  const response = await fetch(`${API_BASE}/applications/${applicationId}/kyc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to submit KYC');
  }
  return response.json();
}

export async function getDocumentTypes() {
  const response = await fetch(`${API_BASE}/document-types`);
  if (!response.ok) throw new Error('Failed to fetch document types');
  return response.json();
}

// ==================== Constants ====================

const STATUS_COLORS = {
  DRAFT: 'default',
  SUBMITTED: 'info',
  UNDER_REVIEW: 'warning',
  PENDING_BIOMETRICS: 'secondary',
  PENDING_KYC: 'secondary',
  PENDING_APPROVAL: 'warning',
  APPROVED: 'success',
  REJECTED: 'error',
  ISSUED: 'success',
};

const CHECK_STATUS_COLORS = {
  PENDING: 'default',
  IN_PROGRESS: 'info',
  PASSED: 'success',
  FAILED: 'error',
  REQUIRES_MANUAL_REVIEW: 'warning',
  SKIPPED: 'default',
};

const CHECK_TYPE_ICONS = {
  IDENTITY_VERIFICATION: PersonIcon,
  BIOMETRIC_ENROLLMENT: FingerprintIcon,
  CRIMINAL_HISTORY: SecurityIcon,
  DOCUMENT_VERIFICATION: DocumentIcon,
  SECURITY_CLEARANCE: SecurityIcon,
  EMPLOYMENT_VERIFICATION: ApplicationIcon,
  ADDRESS_VERIFICATION: ApplicationIcon,
  FINANCIAL_CHECK: ApplicationIcon,
};

const normalizeEnumValue = (value) => (
  value ? value.toString().replace(/-/g, '_').toUpperCase() : ''
);

const normalizeCheckStatus = (value) => {
  const normalized = normalizeEnumValue(value);
  if (normalized === 'COMPLETED_PASSED') return 'PASSED';
  if (normalized === 'COMPLETED_FAILED') return 'FAILED';
  if (normalized === 'COMPLETED_CONDITIONAL') return 'REQUIRES_MANUAL_REVIEW';
  return normalized;
};

const formatStatusLabel = (value) => (
  value
    ? value
        .toLowerCase()
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ')
    : 'Unknown'
);

const DOCUMENT_TYPES = [
  { value: 'PASSPORT', label: 'Passport', description: 'Standard passport' },
  { value: 'PASSPORT_RENEWAL', label: 'Passport Renewal', description: 'Renew existing passport' },
  { value: 'VISA', label: 'Visa', description: 'Travel visa' },
  { value: 'TRAVEL_PERMIT', label: 'Travel Permit', description: 'Temporary travel permit' },
  { value: 'DIPLOMATIC_CREDENTIAL', label: 'Diplomatic Credential', description: 'Diplomatic passport' },
  { value: 'EMERGENCY_TRAVEL_DOCUMENT', label: 'Emergency Travel Document', description: 'Emergency issuance' },
];

const NATIONALITIES = [
  { code: 'USA', name: 'United States' },
  { code: 'GBR', name: 'United Kingdom' },
  { code: 'CAN', name: 'Canada' },
  { code: 'AUS', name: 'Australia' },
  { code: 'DEU', name: 'Germany' },
  { code: 'FRA', name: 'France' },
  { code: 'JPN', name: 'Japan' },
  // Add more as needed
];

// ==================== Utility Functions ====================

function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleDateString();
}

function formatDateTime(dateStr) {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleString();
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// ==================== BiometricCapture Component ====================

/**
 * Component for capturing facial biometrics using webcam.
 * Provides live video preview and capture functionality.
 */
export function BiometricCapture({ onCapture, biometricType = 'FACIAL', disabled = false }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const [stream, setStream] = useState(null);
  const [capturedImage, setCapturedImage] = useState(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [error, setError] = useState(null);

  const startCamera = async () => {
    try {
      const mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'user', width: 640, height: 480 },
        audio: false,
      });
      setStream(mediaStream);
      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
      }
      setIsCapturing(true);
      setError(null);
    } catch (err) {
      setError('Failed to access camera. Please grant camera permissions.');
      console.error('Camera access error:', err);
    }
  };

  const stopCamera = () => {
    if (stream) {
      stream.getTracks().forEach(track => track.stop());
      setStream(null);
    }
    setIsCapturing(false);
  };

  const captureImage = () => {
    if (!videoRef.current || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const video = videoRef.current;
    const context = canvas.getContext('2d');

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    context.drawImage(video, 0, 0);

    const imageData = canvas.toDataURL('image/jpeg', 0.9);
    setCapturedImage(imageData);
    stopCamera();

    // Convert to base64 for API
    const base64Data = imageData.split(',')[1];
    onCapture?.({
      biometric_type: biometricType,
      template_data_base64: base64Data, // In production, this would be processed to ISO 19794 template
      image_data_base64: base64Data,
      capture_quality_score: 0.95, // In production, quality would be calculated
      is_live_capture: true,
    });
  };

  const retake = () => {
    setCapturedImage(null);
    startCamera();
  };

  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, []);

  const getBiometricIcon = () => {
    switch (biometricType) {
      case 'FINGERPRINT':
        return <FingerprintIcon sx={{ fontSize: 48 }} />;
      case 'IRIS':
        return <IrisIcon sx={{ fontSize: 48 }} />;
      default:
        return <FaceIcon sx={{ fontSize: 48 }} />;
    }
  };

  return (
    <Box sx={{ textAlign: 'center' }}>
      <Typography variant="h6" gutterBottom>
        {biometricType === 'FACIAL' ? 'Facial Capture' : `${biometricType} Capture`}
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box
        sx={{
          width: 320,
          height: 240,
          mx: 'auto',
          mb: 2,
          border: '2px solid',
          borderColor: capturedImage ? 'success.main' : 'grey.400',
          borderRadius: 2,
          overflow: 'hidden',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: 'grey.100',
        }}
      >
        {capturedImage ? (
          <img src={capturedImage} alt="Captured" style={{ maxWidth: '100%', maxHeight: '100%' }} />
        ) : isCapturing ? (
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            style={{ maxWidth: '100%', maxHeight: '100%' }}
          />
        ) : (
          <Box sx={{ textAlign: 'center', p: 2 }}>
            {getBiometricIcon()}
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
              Click "Start Camera" to begin capture
            </Typography>
          </Box>
        )}
      </Box>

      <canvas ref={canvasRef} style={{ display: 'none' }} />

      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
        {!isCapturing && !capturedImage && (
          <Button
            variant="contained"
            startIcon={<CameraIcon />}
            onClick={startCamera}
            disabled={disabled}
          >
            Start Camera
          </Button>
        )}
        {isCapturing && (
          <>
            <Button
              variant="contained"
              color="primary"
              startIcon={<PhotoCameraIcon />}
              onClick={captureImage}
            >
              Capture
            </Button>
            <Button variant="outlined" onClick={stopCamera}>
              Cancel
            </Button>
          </>
        )}
        {capturedImage && (
          <>
            <Button variant="outlined" onClick={retake}>
              Retake
            </Button>
            <Chip icon={<CheckIcon />} label="Captured" color="success" />
          </>
        )}
      </Box>
    </Box>
  );
}

// ==================== ApplicantRegistration Component ====================

/**
 * Component for new applicant registration with biometric enrollment.
 */
export function ApplicantRegistration({ userId, onComplete, onCancel }) {
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Form state
  const [formData, setFormData] = useState({
    given_name: '',
    family_name: '',
    email: '',
    phone_number: '',
    date_of_birth: '',
    nationality: 'USA',
    address: {
      street_line1: '',
      street_line2: '',
      city: '',
      state_province: '',
      postal_code: '',
      country: 'USA',
    },
  });
  
  const [createdApplicant, setCreatedApplicant] = useState(null);
  const [biometricData, setBiometricData] = useState(null);

  const handleFormChange = (field, value) => {
    if (field.startsWith('address.')) {
      const addressField = field.replace('address.', '');
      setFormData(prev => ({
        ...prev,
        address: { ...prev.address, [addressField]: value },
      }));
    } else {
      setFormData(prev => ({ ...prev, [field]: value }));
    }
  };

  const handleCreateApplicant = async () => {
    setLoading(true);
    setError(null);
    try {
      const applicant = await createApplicant({
        user_id: userId,
        ...formData,
      });
      setCreatedApplicant(applicant);
      setActiveStep(1);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBiometricCapture = (data) => {
    setBiometricData(data);
  };

  const handleEnrollBiometric = async () => {
    if (!createdApplicant || !biometricData) return;

    setLoading(true);
    setError(null);
    try {
      await enrollBiometric(createdApplicant.id, biometricData);
      setActiveStep(2);
      // Complete registration
      onComplete?.(createdApplicant);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const steps = [
    { label: 'Personal Information', description: 'Enter your details' },
    { label: 'Biometric Enrollment', description: 'Capture facial biometric' },
    { label: 'Complete', description: 'Registration complete' },
  ];

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
        {/* Step 1: Personal Information */}
        <Step>
          <StepLabel>{steps[0].label}</StepLabel>
          <StepContent>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              {steps[0].description}
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
                    {NATIONALITIES.map(n => (
                      <MenuItem key={n.code} value={n.code}>{n.name}</MenuItem>
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
                disabled={loading || !formData.given_name || !formData.family_name || !formData.email}
              >
                {loading ? <CircularProgress size={24} /> : 'Continue'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        {/* Step 2: Biometric Enrollment */}
        <Step>
          <StepLabel>{steps[1].label}</StepLabel>
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

        {/* Step 3: Complete */}
        <Step>
          <StepLabel>{steps[2].label}</StepLabel>
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

// ==================== ApplicationWizard Component ====================

/**
 * Wizard for creating and submitting travel document applications.
 */
export function ApplicationWizard({ applicant, onComplete, onCancel }) {
  const branding = useBranding();
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [documentTypes, setDocumentTypes] = useState([]);
  
  const [formData, setFormData] = useState({
    document_type: 'PASSPORT',
    issuing_authority: branding.issuingAuthority,
    requested_validity_years: 10,
    travel_purpose: '',
    destination_countries: [],
    is_expedited: false,
  });
  
  const [createdApplication, setCreatedApplication] = useState(null);

  useEffect(() => {
    loadDocumentTypes();
  }, []);

  const loadDocumentTypes = async () => {
    try {
      const types = await getDocumentTypes();
      setDocumentTypes(types);
    } catch (err) {
      console.error('Failed to load document types:', err);
    }
  };

  const handleFormChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleCreateApplication = async () => {
    setLoading(true);
    setError(null);
    try {
      const application = await createApplication({
        applicant_id: applicant.id,
        ...formData,
      });
      setCreatedApplication(application);
      setActiveStep(1);
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
      const submitted = await submitApplication(createdApplication.id);
      setCreatedApplication(submitted);
      setActiveStep(2);
      onComplete?.(submitted);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const steps = [
    { label: 'Document Type', description: 'Select document and options' },
    { label: 'Review', description: 'Review and submit application' },
    { label: 'Submitted', description: 'Application submitted for vetting' },
  ];

  const selectedType = documentTypes.find(t => t.document_type === formData.document_type);

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
        {/* Step 1: Document Type Selection */}
        <Step>
          <StepLabel>{steps[0].label}</StepLabel>
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
                    {DOCUMENT_TYPES.map(dt => (
                      <MenuItem key={dt.value} value={dt.value}>
                        {dt.label} - {dt.description}
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
                      {selectedType.requirements?.map((req, idx) => (
                        <ListItem key={idx} sx={{ py: 0 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            {req.required ? <CheckIcon color="primary" fontSize="small" /> : <PendingIcon fontSize="small" />}
                          </ListItemIcon>
                          <ListItemText
                            primary={req.check_type.replace(/_/g, ' ')}
                            secondary={req.required ? 'Required' : 'Optional'}
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

              {(formData.document_type === 'VISA') && (
                <>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Travel Purpose"
                      value={formData.travel_purpose}
                      onChange={(e) => handleFormChange('travel_purpose', e.target.value)}
                    />
                  </Grid>
                </>
              )}
            </Grid>

            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button onClick={onCancel}>Cancel</Button>
              <Button
                variant="contained"
                onClick={handleCreateApplication}
                disabled={loading}
              >
                {loading ? <CircularProgress size={24} /> : 'Continue'}
              </Button>
            </Box>
          </StepContent>
        </Step>

        {/* Step 2: Review */}
        <Step>
          <StepLabel>{steps[1].label}</StepLabel>
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

        {/* Step 3: Submitted */}
        <Step>
          <StepLabel>{steps[2].label}</StepLabel>
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

// ==================== VettingDashboard Component ====================

/**
 * Dashboard for reviewing and processing vetting checks.
 */
export function VettingDashboard() {
  const [applications, setApplications] = useState([]);
  const [pendingChecks, setPendingChecks] = useState([]);
  const [selectedApplication, setSelectedApplication] = useState(null);
  const [applicationDetails, setApplicationDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Dialog states
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [approveDialogOpen, setApproveDialogOpen] = useState(false);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  
  // Form state
  const [approvalNotes, setApprovalNotes] = useState('');
  const [rejectionReason, setRejectionReason] = useState('');

  const detailStatus = applicationDetails
    ? normalizeEnumValue(applicationDetails.application.status)
    : '';

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [appsData, checksData] = await Promise.all([
        listApplications({ limit: 50 }),
        getPendingChecks(),
      ]);
      setApplications(appsData.applications || []);
      setPendingChecks(checksData || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleViewDetails = async (application) => {
    setSelectedApplication(application);
    try {
      const details = await getApplication(application.id);
      setApplicationDetails(details);
      setDetailDialogOpen(true);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleApprove = async () => {
    if (!selectedApplication) return;
    setLoading(true);
    try {
      await approveApplication(selectedApplication.id, {
        approved_by: 'admin', // In production, get from auth
        notes: approvalNotes,
      });
      setSuccess('Application approved successfully');
      setApproveDialogOpen(false);
      setApprovalNotes('');
      loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReject = async () => {
    if (!selectedApplication) return;
    setLoading(true);
    try {
      await rejectApplication(selectedApplication.id, {
        rejected_by: 'admin',
        reason: rejectionReason,
      });
      setSuccess('Application rejected');
      setRejectDialogOpen(false);
      setRejectionReason('');
      loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCompleteCheck = async (checkId, passed) => {
    setLoading(true);
    try {
      await completeCheck(checkId, {
        passed,
        performed_by: 'admin',
        notes: passed ? 'Manually verified' : 'Failed verification',
      });
      setSuccess(`Check ${passed ? 'passed' : 'failed'}`);
      loadData();
      if (applicationDetails) {
        const details = await getApplication(selectedApplication.id);
        setApplicationDetails(details);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    const normalized = normalizeCheckStatus(status);
    switch (normalized) {
      case 'PASSED':
        return <PassedIcon color="success" />;
      case 'FAILED':
        return <FailedIcon color="error" />;
      case 'IN_PROGRESS':
        return <CircularProgress size={20} />;
      case 'REQUIRES_MANUAL_REVIEW':
        return <WarningIcon color="warning" />;
      default:
        return <PendingIcon color="disabled" />;
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">Vetting Dashboard</Typography>
        <IconButton onClick={loadData} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}>
        <Alert severity="error" onClose={() => setError(null)}>{error}</Alert>
      </Snackbar>
      <Snackbar open={!!success} autoHideDuration={3000} onClose={() => setSuccess(null)}>
        <Alert severity="success" onClose={() => setSuccess(null)}>{success}</Alert>
      </Snackbar>

      {/* Stats Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Pending Review</Typography>
              <Typography variant="h4">
                {applications.filter(a => normalizeEnumValue(a.status) === 'PENDING_APPROVAL').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Under Review</Typography>
              <Typography variant="h4">
                {applications.filter(a => normalizeEnumValue(a.status) === 'UNDER_REVIEW').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Pending Checks</Typography>
              <Typography variant="h4">{pendingChecks.length}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Approved Today</Typography>
              <Typography variant="h4" color="success.main">
                {applications.filter(a => 
                  normalizeEnumValue(a.status) === 'APPROVED' && 
                  new Date(a.approved_at).toDateString() === new Date().toDateString()
                ).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)} sx={{ mb: 2 }}>
        <Tab label="All Applications" />
        <Tab label="Pending Approval" />
        <Tab label="Pending Checks" />
      </Tabs>

      {/* Applications Table */}
      {loading && <LinearProgress sx={{ mb: 2 }} />}

      <TableContainer component={Paper} data-testid="applications-table">
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Reference</TableCell>
              <TableCell>Document Type</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Submitted</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {applications
              .filter(app => {
                if (tabValue === 1) return normalizeEnumValue(app.status) === 'PENDING_APPROVAL';
                return true;
              })
              .map(app => {
                const normalizedStatus = normalizeEnumValue(app.status);
                return (
                <TableRow key={app.id} data-testid={`application-row-${app.id}`}>
                  <TableCell>{app.reference_number}</TableCell>
                  <TableCell>{app.document_type}</TableCell>
                  <TableCell>
                    <Chip
                      label={formatStatusLabel(normalizedStatus)}
                      color={STATUS_COLORS[normalizedStatus] || 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{formatDate(app.submitted_at)}</TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={() => handleViewDetails(app)}
                      data-testid="view-application-btn"
                    >
                      <ViewIcon />
                    </IconButton>
                    {normalizedStatus === 'PENDING_APPROVAL' && (
                      <>
                        <IconButton
                          size="small"
                          color="success"
                          onClick={() => {
                            setSelectedApplication(app);
                            setApproveDialogOpen(true);
                          }}
                          data-testid="approve-application-btn"
                        >
                          <CheckIcon />
                        </IconButton>
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => {
                            setSelectedApplication(app);
                            setRejectDialogOpen(true);
                          }}
                          data-testid="reject-application-btn"
                        >
                          <CancelIcon />
                        </IconButton>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              );
              })}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Application Details Dialog */}
      <Dialog
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(false)}
        maxWidth="md"
        fullWidth
        data-testid="application-detail-view"
      >
        <DialogTitle>Application Details</DialogTitle>
        <DialogContent>
          {applicationDetails && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Reference</Typography>
                  <Typography>{applicationDetails.application.reference_number}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Status</Typography>
                  <Chip
                    label={formatStatusLabel(detailStatus)}
                    color={STATUS_COLORS[detailStatus] || 'default'}
                    size="small"
                  />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Applicant</Typography>
                  <Typography>{applicationDetails.applicant?.full_name}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Document Type</Typography>
                  <Typography>{applicationDetails.application.document_type}</Typography>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom>Vetting Checks</Typography>
              <List>
                {applicationDetails.vetting_checks?.map(check => {
                  const normalizedCheckType = normalizeEnumValue(check.check_type);
                  const normalizedCheckStatus = normalizeCheckStatus(check.status);
                  const IconComponent = CHECK_TYPE_ICONS[normalizedCheckType] || SecurityIcon;
                  return (
                    <ListItem key={check.id} divider>
                      <ListItemIcon>
                        <IconComponent />
                      </ListItemIcon>
                      <ListItemText
                        primary={formatStatusLabel(normalizedCheckType)}
                        secondary={check.notes || ((check.is_required ?? check.is_mandatory) ? 'Required' : 'Optional')}
                      />
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Chip
                          label={formatStatusLabel(normalizedCheckStatus)}
                          color={CHECK_STATUS_COLORS[normalizedCheckStatus]}
                          size="small"
                        />
                        {normalizedCheckStatus === 'PENDING' && (
                          <>
                            <IconButton
                              size="small"
                              color="success"
                              onClick={() => handleCompleteCheck(check.id, true)}
                              data-testid={`check-pass-btn-${check.id}`}
                            >
                              <PassedIcon />
                            </IconButton>
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleCompleteCheck(check.id, false)}
                              data-testid={`check-fail-btn-${check.id}`}
                            >
                              <FailedIcon />
                            </IconButton>
                          </>
                        )}
                      </Box>
                    </ListItem>
                  );
                })}
              </List>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Approve Dialog */}
      <Dialog
        open={approveDialogOpen}
        onClose={() => setApproveDialogOpen(false)}
        data-testid="approval-dialog"
      >
        <DialogTitle>Approve Application</DialogTitle>
        <DialogContent>
          <Typography sx={{ mb: 2 }}>
            Approve application {selectedApplication?.reference_number}?
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={3}
            label="Notes (optional)"
            value={approvalNotes}
            onChange={(e) => setApprovalNotes(e.target.value)}
            data-testid="approval-notes"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApproveDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="success"
            onClick={handleApprove}
            disabled={loading}
            data-testid="confirm-approval-btn"
          >
            Approve
          </Button>
        </DialogActions>
      </Dialog>

      {/* Reject Dialog */}
      <Dialog
        open={rejectDialogOpen}
        onClose={() => setRejectDialogOpen(false)}
        data-testid="rejection-dialog"
      >
        <DialogTitle>Reject Application</DialogTitle>
        <DialogContent>
          <Typography sx={{ mb: 2 }}>
            Reject application {selectedApplication?.reference_number}?
          </Typography>
          <TextField
            fullWidth
            required
            multiline
            rows={3}
            label="Reason"
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            data-testid="rejection-reason"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRejectDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleReject}
            disabled={loading || !rejectionReason}
            data-testid="confirm-reject-btn"
          >
            Reject
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// ==================== ApprovedApplicantSelector Component ====================

/**
 * Component for selecting an approved applicant when issuing a document.
 * This integrates with TravelDocuments to auto-fill holder information.
 */
export function ApprovedApplicantSelector({ onSelect, disabled }) {
  const [approvedApps, setApprovedApps] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);

  useEffect(() => {
    loadApprovedApplications();
  }, []);

  const loadApprovedApplications = async () => {
    setLoading(true);
    try {
      const apps = await getApprovedApplications();
      setApprovedApps(apps);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSelect = (app) => {
    setSelectedApp(app);
    onSelect?.(app);
  };

  if (loading) {
    return <CircularProgress size={24} />;
  }

  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  if (approvedApps.length === 0) {
    return (
      <Alert severity="info">
        No approved applications available. Applicants must complete vetting before document issuance.
      </Alert>
    );
  }

  return (
    <FormControl fullWidth disabled={disabled}>
      <InputLabel>Select Approved Applicant</InputLabel>
      <Select
        value={selectedApp?.application_id || ''}
        label="Select Approved Applicant"
        onChange={(e) => {
          const app = approvedApps.find(a => a.application_id === e.target.value);
          handleSelect(app);
        }}
      >
        {approvedApps.map(app => (
          <MenuItem key={app.application_id} value={app.application_id}>
            <Box>
              <Typography variant="body1">{app.applicant_name}</Typography>
              <Typography variant="caption" color="textSecondary">
                {app.reference_number} - {app.document_type}
              </Typography>
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}

export default VettingDashboard;
