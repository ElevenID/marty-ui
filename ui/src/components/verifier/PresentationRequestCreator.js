import React, { useState } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  TextField,
  Box,
  Alert,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Divider,
  Snackbar,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  QrCode2 as QrCodeIcon,
  ContentCopy as CopyIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  CheckCircle as CheckIcon,
  Schedule as PendingIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { QRCodeSVG } from 'qrcode.react';

/**
 * Credential types supported for presentation requests
 */
const CREDENTIAL_TYPES = [
  { value: 'mDL', label: 'Mobile Driving License (mDL)', attributes: ['given_name', 'family_name', 'birth_date', 'age_over_21', 'document_number'] },
  { value: 'VerifiableId', label: 'Verifiable ID', attributes: ['given_name', 'family_name', 'birth_date', 'nationality'] },
  { value: 'VerifiableDiploma', label: 'Verifiable Diploma', attributes: ['degree', 'institution', 'graduation_date'] },
  { value: 'ProofOfAge', label: 'Proof of Age', attributes: ['age_over_18', 'age_over_21'] },
];

/**
 * PresentationRequestCreator - Component for creating OID4VP presentation requests
 * 
 * This component allows verifiers to:
 * 1. Select credential types to request
 * 2. Generate QR codes containing presentation requests
 * 3. Monitor submission status
 * 4. View submitted presentations
 */
const PresentationRequestCreator = () => {
  // Form state
  const [selectedCredentialType, setSelectedCredentialType] = useState('mDL');
  const [customNonce, setCustomNonce] = useState('');
  const [verifierName, setVerifierName] = useState('Demo Verifier');
  
  // Request state
  const [requestId, setRequestId] = useState(null);
  const [requestUri, setRequestUri] = useState('');
  const [requestAudience, setRequestAudience] = useState('');
  const [requestStatus, setRequestStatus] = useState('idle'); // idle, created, pending, submitted, verified, error
  const [presentationData, setPresentationData] = useState(null);
  
  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copySnackbar, setCopySnackbar] = useState(false);

  /**
   * Generate a new presentation request
   */
  const createPresentationRequest = async () => {
    setLoading(true);
    setError(null);
    setRequestStatus('idle');
    setPresentationData(null);

    try {
      const nonce = customNonce || `nonce-${Date.now()}-${Math.random().toString(36).substring(7)}`;
      
      const response = await fetch('/api/verifier/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requested_credentials: [selectedCredentialType],
          verifier_id: verifierName,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to create request: ${response.statusText}`);
      }

      const data = await response.json();
      
      setRequestId(data.request_id);
      setRequestUri(data.request_uri || '');
      setRequestAudience(data.audience || '');
      setRequestStatus('pending');
    } catch (err) {
      setError(err.message);
      setRequestStatus('error');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Verify the submitted presentation
   */
  const verifyPresentation = async () => {
    if (!presentationData) return;

    setLoading(true);
    try {
      const response = await fetch('/api/verifier/verify-presentation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          presentation_jwt: presentationData.vp_jwt || presentationData,
          expected_nonce: customNonce || null,
          expected_audience: requestAudience || verifierName,
        }),
      });

      const result = await response.json();
      
      if (result.valid) {
        setRequestStatus('verified');
      } else {
        setError(result.error || 'Verification failed');
        setRequestStatus('error');
      }
    } catch (err) {
      setError(err.message);
      setRequestStatus('error');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Copy request URI to clipboard
   */
  const copyToClipboard = async () => {
    if (requestUri) {
      await navigator.clipboard.writeText(requestUri);
      setCopySnackbar(true);
    }
  };

  /**
   * Reset the form
   */
  const resetForm = () => {
    setRequestId(null);
    setRequestUri('');
    setRequestStatus('idle');
    setPresentationData(null);
    setError(null);
    setCustomNonce('');
  };

  /**
   * Get status chip properties
   */
  const getStatusChip = () => {
    switch (requestStatus) {
      case 'pending':
        return { label: 'Waiting for Presentation', color: 'warning', icon: <PendingIcon /> };
      case 'submitted':
        return { label: 'Presentation Received', color: 'info', icon: <CheckIcon /> };
      case 'verified':
        return { label: 'Verified', color: 'success', icon: <CheckIcon /> };
      case 'error':
        return { label: 'Error', color: 'error', icon: <ErrorIcon /> };
      default:
        return null;
    }
  };

  const statusChip = getStatusChip();

  return (
    <Container maxWidth="lg" data-testid="presentation-request-creator">
      <Paper sx={{ p: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center" data-testid="verifier-title">
          <SecurityIcon sx={{ fontSize: 48, mr: 2, verticalAlign: 'middle' }} />
          Create Presentation Request
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph align="center">
          Generate an OID4VP presentation request QR code for wallets to scan.
        </Typography>

        <Grid container spacing={3}>
          {/* Configuration Panel */}
          <Grid item xs={12} md={6}>
            <Card data-testid="request-config-card">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Request Configuration
                </Typography>

                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel id="credential-type-label">Credential Type</InputLabel>
                  <Select
                    labelId="credential-type-label"
                    value={selectedCredentialType}
                    label="Credential Type"
                    onChange={(e) => setSelectedCredentialType(e.target.value)}
                    disabled={requestStatus === 'pending'}
                    data-testid="credential-type-select"
                  >
                    {CREDENTIAL_TYPES.map((type) => (
                      <MenuItem key={type.value} value={type.value} data-testid={`credential-type-${type.value}`}>
                        {type.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <TextField
                  fullWidth
                  label="Verifier Name"
                  value={verifierName}
                  onChange={(e) => setVerifierName(e.target.value)}
                  disabled={requestStatus === 'pending'}
                  sx={{ mb: 2 }}
                  data-testid="verifier-name-input"
                />

                <TextField
                  fullWidth
                  label="Custom Nonce (optional)"
                  value={customNonce}
                  onChange={(e) => setCustomNonce(e.target.value)}
                  disabled={requestStatus === 'pending'}
                  placeholder="Leave blank to auto-generate"
                  helperText="Used to prevent replay attacks"
                  sx={{ mb: 2 }}
                  data-testid="nonce-input"
                />

                <Divider sx={{ my: 2 }} />

                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Requested Attributes:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                  {CREDENTIAL_TYPES.find(t => t.value === selectedCredentialType)?.attributes.map((attr) => (
                    <Chip key={attr} label={attr} size="small" variant="outlined" data-testid={`attribute-chip-${attr}`} />
                  ))}
                </Box>

                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    onClick={createPresentationRequest}
                    disabled={loading || requestStatus === 'pending'}
                    startIcon={loading ? <CircularProgress size={20} /> : <QrCodeIcon />}
                    fullWidth
                    data-testid="create-request-button"
                  >
                    {loading ? 'Creating...' : 'Create Request'}
                  </Button>

                  {requestStatus !== 'idle' && (
                    <Button
                      variant="outlined"
                      onClick={resetForm}
                      startIcon={<RefreshIcon />}
                      data-testid="reset-button"
                    >
                      Reset
                    </Button>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* QR Code Panel */}
          <Grid item xs={12} md={6}>
            <Card data-testid="qr-code-card">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Presentation Request QR Code
                </Typography>

                {statusChip && (
                  <Box sx={{ mb: 2 }}>
                    <Chip
                      label={statusChip.label}
                      color={statusChip.color}
                      icon={statusChip.icon}
                      data-testid="request-status-chip"
                    />
                  </Box>
                )}

                {error && (
                  <Alert severity="error" sx={{ mb: 2 }} data-testid="error-alert">
                    {error}
                  </Alert>
                )}

                {requestUri ? (
                  <Box sx={{ textAlign: 'center' }}>
                    <Box
                      sx={{
                        display: 'inline-block',
                        p: 2,
                        bgcolor: 'white',
                        borderRadius: 2,
                        mb: 2,
                      }}
                      data-testid="qr-code-container"
                    >
                      <QRCodeSVG
                        value={requestUri}
                        size={256}
                        level="M"
                        includeMargin
                        data-testid="qr-code"
                      />
                    </Box>

                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <TextField
                        fullWidth
                        size="small"
                        value={requestUri}
                        InputProps={{ readOnly: true }}
                        data-testid="request-uri-input"
                      />
                      <Tooltip title="Copy to clipboard">
                        <IconButton onClick={copyToClipboard} data-testid="copy-uri-button">
                          <CopyIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>

                    {requestId && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }} data-testid="request-id-display">
                        Request ID: {requestId}
                      </Typography>
                    )}
                  </Box>
                ) : (
                  <Box
                    sx={{
                      height: 300,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      bgcolor: 'grey.100',
                      borderRadius: 2,
                    }}
                    data-testid="qr-placeholder"
                  >
                    <Typography color="text.secondary">
                      QR code will appear here
                    </Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* Presentation Data Panel */}
          {presentationData && (
            <Grid item xs={12}>
              <Card data-testid="presentation-data-card">
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">
                      Received Presentation
                    </Typography>
                    {requestStatus === 'submitted' && (
                      <Button
                        variant="contained"
                        color="primary"
                        onClick={verifyPresentation}
                        disabled={loading}
                        startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
                        data-testid="verify-presentation-button"
                      >
                        {loading ? 'Verifying...' : 'Verify Presentation'}
                      </Button>
                    )}
                  </Box>

                  {requestStatus === 'verified' && (
                    <Alert severity="success" sx={{ mb: 2 }} data-testid="verification-success-alert">
                      Presentation verified successfully!
                    </Alert>
                  )}

                  <Box
                    component="pre"
                    sx={{
                      backgroundColor: 'grey.100',
                      p: 2,
                      borderRadius: 1,
                      overflow: 'auto',
                      fontSize: '0.875rem',
                      maxHeight: 400,
                    }}
                    data-testid="presentation-json"
                  >
                    {JSON.stringify(presentationData, null, 2)}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </Paper>

      <Snackbar
        open={copySnackbar}
        autoHideDuration={2000}
        onClose={() => setCopySnackbar(false)}
        message="Copied to clipboard"
        data-testid="copy-snackbar"
      />
    </Container>
  );
};

export default PresentationRequestCreator;
