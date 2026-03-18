import { useState } from 'react';
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
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  VerifiedUser as VerifiedIcon,
  Error as ErrorIcon,
  QrCodeScanner as ScanIcon,
  Security as SecurityIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon
} from '@mui/icons-material';
import {
  createVerifierDemoMockPresentation,
  serializeVerifierDemoPresentation,
  verifyVerifierDemoPresentation,
} from '../application/verifier';

const VerifierDemo = () => {
  const [verificationState, setVerificationState] = useState('ready'); // ready, scanning, verifying, complete
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [presentationData, setPresentationData] = useState('');

  const simulateQRScan = () => {
    setVerificationState('scanning');

    // Simulate QR code scan delay
    setTimeout(() => {
      setPresentationData(
        serializeVerifierDemoPresentation(createVerifierDemoMockPresentation()),
      );
      setVerificationState('ready');
    }, 2000);
  };

  const verifyPresentation = async () => {
    if (!presentationData) {
      alert('Please scan a QR code or enter presentation data first');
      return;
    }

    setLoading(true);
    setVerificationState('verifying');

    try {
      const result = await verifyVerifierDemoPresentation({
        presentationData,
      });

      setVerificationResult(result);
      setVerificationState('complete');
    } catch (error) {
      console.error('Verification failed:', error);
      setVerificationResult(null);
      setVerificationState('complete');
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setVerificationState('ready');
    setVerificationResult(null);
    setPresentationData('');
    setLoading(false);
  };

  const renderVerificationChecks = () => {
    if (!verificationResult?.checks) return null;

    return (
      <List>
        {verificationResult.checks.map((check, index) => (
          <ListItem key={index}>
            <ListItemIcon>
              {check.passed ? (
                <CheckIcon color="success" />
              ) : (
                <CancelIcon color="error" />
              )}
            </ListItemIcon>
            <ListItemText
              primary={check.check_name}
              secondary={check.details || check.description}
            />
          </ListItem>
        ))}
      </List>
    );
  };

  return (
    <Container maxWidth="md" data-testid="verifier-demo">
      <Paper sx={{ p: 3 }} data-testid="verifier-demo-paper">
        <Typography variant="h4" component="h1" gutterBottom align="center" data-testid="verifier-title">
          <VerifiedIcon sx={{ fontSize: 48, mr: 2, verticalAlign: 'middle' }} />
          Credential Verifier
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph align="center">
          Verify mobile driving license (mDL) and mDoc presentations.
          Scan a QR code or paste presentation data to verify credentials.
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  <ScanIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  1. Capture Presentation
                </Typography>

                <Box sx={{ mb: 2 }}>
                  <Button
                    variant="outlined"
                    onClick={simulateQRScan}
                    disabled={verificationState === 'scanning' || loading}
                    fullWidth
                    sx={{ mb: 2 }}
                    data-testid="scan-qr-button"
                  >
                    {verificationState === 'scanning' ? (
                      <>
                        <CircularProgress size={20} sx={{ mr: 1 }} />
                        Scanning QR Code...
                      </>
                    ) : (
                      'Simulate QR Code Scan'
                    )}
                  </Button>

                  <Typography variant="body2" color="text.secondary" align="center">
                    OR
                  </Typography>

                  <TextField
                    fullWidth
                    multiline
                    rows={4}
                    label="Paste Presentation Data"
                    value={presentationData}
                    onChange={(e) => setPresentationData(e.target.value)}
                    sx={{ mt: 2 }}
                    placeholder="Paste verifiable presentation JSON..."
                    data-testid="presentation-data-input"
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  2. Verify Credential
                </Typography>

                <Button
                  variant="contained"
                  onClick={verifyPresentation}
                  disabled={!presentationData || loading || verificationState === 'verifying'}
                  fullWidth
                  sx={{ mb: 2 }}
                  data-testid="verify-button"
                >
                  {verificationState === 'verifying' ? (
                    <>
                      <CircularProgress size={20} sx={{ mr: 1 }} />
                      Verifying...
                    </>
                  ) : (
                    'Verify Presentation'
                  )}
                </Button>

                {verificationState === 'complete' && (
                  <Button
                    variant="outlined"
                    onClick={reset}
                    fullWidth
                    data-testid="reset-button"
                  >
                    Reset
                  </Button>
                )}
              </CardContent>
            </Card>
          </Grid>

          {presentationData && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="h6">Presentation Data</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box
                        component="pre"
                        sx={{
                          backgroundColor: 'grey.100',
                          p: 2,
                          borderRadius: 1,
                          overflow: 'auto',
                          fontSize: '0.875rem'
                        }}
                      >
                        {presentationData}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                </CardContent>
              </Card>
            </Grid>
          )}

          {verificationResult && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Verification Result
                  </Typography>

                  <Box sx={{ mb: 2 }}>
                    <Chip
                      label={verificationResult.verified ? 'VERIFIED' : 'VERIFICATION FAILED'}
                      color={verificationResult.verified ? 'success' : 'error'}
                      icon={verificationResult.verified ? <VerifiedIcon /> : <ErrorIcon />}
                      size="large"
                      data-testid="verification-result-chip"
                    />
                  </Box>

                  {verificationResult.verified ? (
                    <Alert severity="success" sx={{ mb: 2 }} data-testid="verification-success-alert">
                      Credential verification successful! The presentation is valid and trustworthy.
                    </Alert>
                  ) : (
                    <Alert severity="error" sx={{ mb: 2 }} data-testid="verification-error-alert">
                      {verificationResult.error || 'Credential verification failed'}
                    </Alert>
                  )}

                  {verificationResult.checks && verificationResult.checks.length > 0 && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">Verification Checks</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {renderVerificationChecks()}
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {verificationResult.presentation_summary && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="h6">Presentation Summary</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <pre>{JSON.stringify(verificationResult.presentation_summary, null, 2)}</pre>
                      </AccordionDetails>
                    </Accordion>
                  )}
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </Paper>
    </Container>
  );
};

export default VerifierDemo;
