import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  Box,
  Alert,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Verified as VerifiedIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  QrCode as QrCodeIcon,
  Shield as ShieldIcon,
  Policy as PolicyIcon
} from '@mui/icons-material';

const EnhancedVerifierDemo = () => {
  const [selectedFeature, setSelectedFeature] = useState('age-verification');
  const [ageVerificationState, setAgeVerificationState] = useState({
    useCase: 'alcohol_purchase',
    request: null,
    result: null,
    loading: false
  });
  const [offlineQRState, setOfflineQRState] = useState({
    qrCode: null,
    verificationResult: null,
    loading: false
  });
  const [certificateState, setCertificateState] = useState({
    dashboard: null,
    selectedCert: null,
    loading: false
  });
  const [policyState, setPolicyState] = useState({
    evaluation: null,
    policies: null,
    loading: false
  });
  const [dialogOpen, setDialogOpen] = useState(false);

  const ageVerificationUseCases = {
    'alcohol_purchase': 'Alcohol Purchase (21+)',
    'voting_registration': 'Voting Registration (18+)',
    'senior_discount': 'Senior Discount (65+)',
    'employment_eligibility': 'Employment Eligibility (18-65)'
  };

  const handleAgeVerificationRequest = async () => {
    setAgeVerificationState(prev => ({ ...prev, loading: true }));

    try {
      const response = await fetch('/api/verifier/age-verification/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          use_case: ageVerificationState.useCase,
          verifier_id: 'demo_enhanced_verifier',
          purpose: `Enhanced demo for ${ageVerificationUseCases[ageVerificationState.useCase]}`
        })
      });

      const data = await response.json();

      if (data.success) {
        setAgeVerificationState(prev => ({
          ...prev,
          request: data.verification_request,
          loading: false
        }));
      } else {
        throw new Error(data.error || 'Request failed');
      }
    } catch (error) {
      console.error('Age verification request failed:', error);
      setAgeVerificationState(prev => ({ ...prev, loading: false }));
    }
  };

  const simulateAgeVerification = async () => {
    if (!ageVerificationState.request) return;

    setAgeVerificationState(prev => ({ ...prev, loading: true }));

    try {
      // Simulate credential presentation
      const mockPresentation = {
        verifiableCredential: [{
          credentialSubject: {
            age_over_18: true,
            age_over_21: ageVerificationState.useCase === 'alcohol_purchase',
            age_over_65: ageVerificationState.useCase === 'senior_discount',
            given_name: 'Jane',
            age_in_range: ageVerificationState.useCase === 'employment_eligibility'
          },
          issuer: 'did:example:demo:issuer',
          expirationDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        }]
      };

      const response = await fetch('/api/verifier/age-verification/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_id: ageVerificationState.request.request_id,
          presentation: mockPresentation
        })
      });

      const data = await response.json();

      setAgeVerificationState(prev => ({
        ...prev,
        result: data,
        loading: false
      }));
    } catch (error) {
      console.error('Age verification failed:', error);
      setAgeVerificationState(prev => ({ ...prev, loading: false }));
    }
  };

  const handleCreateOfflineQR = async () => {
    setOfflineQRState(prev => ({ ...prev, loading: true }));

    try {
      const mockMDLData = {
        given_name: 'Jane',
        family_name: 'Doe',
        birth_date: '1990-01-01',
        age_over_18: true,
        age_over_21: true,
        document_number: 'DL123456789',
        expiry_date: '2030-01-01',
        issuing_country: 'XX',
        issuing_authority: 'Demo DMV'
      };

      const response = await fetch('/api/verifier/offline-qr/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mdl_data: mockMDLData,
          verification_requirements: {
            required_fields: ['given_name', 'family_name', 'age_over_18'],
            purpose: 'offline_demo',
            context: 'demo'
          },
          expires_in_minutes: 60
        })
      });

      const data = await response.json();

      if (data.success) {
        setOfflineQRState(prev => ({
          ...prev,
          qrCode: data.qr_data,
          loading: false
        }));
      } else {
        throw new Error(data.error || 'QR creation failed');
      }
    } catch (error) {
      console.error('Offline QR creation failed:', error);
      setOfflineQRState(prev => ({ ...prev, loading: false }));
    }
  };

  const handleVerifyOfflineQR = async () => {
    if (!offlineQRState.qrCode) return;

    setOfflineQRState(prev => ({ ...prev, loading: true }));

    try {
      const response = await fetch('/api/verifier/offline-qr/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          qr_data: offlineQRState.qrCode.qr_code_data,
          verification_context: {
            purpose: 'age_verification',
            verifier_id: 'offline_demo_verifier'
          }
        })
      });

      const data = await response.json();

      setOfflineQRState(prev => ({
        ...prev,
        verificationResult: data.result,
        loading: false
      }));
    } catch (error) {
      console.error('Offline QR verification failed:', error);
      setOfflineQRState(prev => ({ ...prev, loading: false }));
    }
  };

  const loadCertificateDashboard = async () => {
    setCertificateState(prev => ({ ...prev, loading: true }));

    try {
      const response = await fetch('/api/verifier/certificates/dashboard');
      const data = await response.json();

      setCertificateState(prev => ({
        ...prev,
        dashboard: data,
        loading: false
      }));
    } catch (error) {
      console.error('Certificate dashboard failed:', error);
      setCertificateState(prev => ({ ...prev, loading: false }));
    }
  };

  const renewCertificate = async (certId) => {
    try {
      const response = await fetch(`/api/verifier/certificates/${certId}/renew`, {
        method: 'POST'
      });
      const data = await response.json();

      if (data.renewal_successful) {
        // Reload dashboard
        await loadCertificateDashboard();
        alert(`Certificate ${certId} renewed successfully!`);
      }
    } catch (error) {
      console.error('Certificate renewal failed:', error);
    }
  };

  const loadPolicySummary = async () => {
    setPolicyState(prev => ({ ...prev, loading: true }));

    try {
      const response = await fetch('/api/verifier/policy/summary');
      const data = await response.json();

      setPolicyState(prev => ({
        ...prev,
        policies: data,
        loading: false
      }));
    } catch (error) {
      console.error('Policy summary failed:', error);
      setPolicyState(prev => ({ ...prev, loading: false }));
    }
  };

  const evaluatePolicy = async () => {
    setPolicyState(prev => ({ ...prev, loading: true }));

    try {
      const mockEvaluation = {
        presentation_request: {
          purpose: 'age_verification',
          requested_attributes: ['age_over_21', 'given_name']
        },
        available_attributes: {
          age_over_21: true,
          given_name: 'Jane',
          family_name: 'Doe',
          birth_date: '1990-01-01',
          address: '123 Demo St'
        },
        context: {
          context_type: 'commercial',
          verifier_trust_level: 'verified_commercial',
          location: 'private_establishment',
          urgency: 'routine'
        }
      };

      const response = await fetch('/api/verifier/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mockEvaluation)
      });

      const data = await response.json();

      setPolicyState(prev => ({
        ...prev,
        evaluation: data,
        loading: false
      }));
    } catch (error) {
      console.error('Policy evaluation failed:', error);
      setPolicyState(prev => ({ ...prev, loading: false }));
    }
  };

  useEffect(() => {
    if (selectedFeature === 'certificates') {
      loadCertificateDashboard();
    } else if (selectedFeature === 'policy') {
      loadPolicySummary();
    }
  }, [selectedFeature]);

  const renderAgeVerificationDemo = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Typography variant="h6" gutterBottom>
          <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Enhanced Age Verification Demo
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Verify age without disclosing birth date using selective disclosure and zero-knowledge proofs.
        </Typography>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6">1. Create Verification Request</Typography>

            <FormControl fullWidth sx={{ mt: 2 }}>
              <InputLabel>Use Case</InputLabel>
              <Select
                value={ageVerificationState.useCase}
                onChange={(e) => setAgeVerificationState(prev => ({ ...prev, useCase: e.target.value }))}
              >
                {Object.entries(ageVerificationUseCases).map(([key, label]) => (
                  <MenuItem key={key} value={key}>{label}</MenuItem>
                ))}
              </Select>
            </FormControl>

            <Button
              variant="contained"
              onClick={handleAgeVerificationRequest}
              disabled={ageVerificationState.loading}
              sx={{ mt: 2 }}
              fullWidth
            >
              Create Request
            </Button>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6">2. Simulate Verification</Typography>

            {ageVerificationState.request && (
              <Box sx={{ mt: 2 }}>
                <Alert severity="info" sx={{ mb: 2 }}>
                  Request created for: {ageVerificationUseCases[ageVerificationState.useCase]}
                </Alert>

                <Button
                  variant="contained"
                  onClick={simulateAgeVerification}
                  disabled={ageVerificationState.loading}
                  fullWidth
                >
                  Simulate Verification
                </Button>
              </Box>
            )}
          </CardContent>
        </Card>
      </Grid>

      {ageVerificationState.result && (
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6">Verification Result</Typography>

              <Box sx={{ mt: 2 }}>
                <Chip
                  label={ageVerificationState.result.verification_result.verified ? 'VERIFIED' : 'FAILED'}
                  color={ageVerificationState.result.verification_result.verified ? 'success' : 'error'}
                  icon={ageVerificationState.result.verification_result.verified ? <VerifiedIcon /> : <ErrorIcon />}
                />

                <Chip
                  label={`Privacy: ${ageVerificationState.result.privacy_report.privacy_level.toUpperCase()}`}
                  color={ageVerificationState.result.privacy_report.privacy_level === 'high' ? 'success' : 'warning'}
                  sx={{ ml: 1 }}
                />
              </Box>

              <Accordion sx={{ mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Privacy Report</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <pre>{JSON.stringify(ageVerificationState.result.privacy_report, null, 2)}</pre>
                </AccordionDetails>
              </Accordion>
            </CardContent>
          </Card>
        </Grid>
      )}
    </Grid>
  );

  const renderOfflineQRDemo = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Typography variant="h6" gutterBottom>
          <QrCodeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Offline QR Code Verification Demo
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Create and verify QR codes that work without network connectivity.
        </Typography>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6">1. Create Offline QR Code</Typography>

            <Button
              variant="contained"
              onClick={handleCreateOfflineQR}
              disabled={offlineQRState.loading}
              sx={{ mt: 2 }}
              fullWidth
            >
              Generate Offline QR
            </Button>

            {offlineQRState.qrCode && (
              <Box sx={{ mt: 2 }}>
                <Alert severity="success">
                  QR Code created! Size: {offlineQRState.qrCode.size_bytes} bytes
                </Alert>

                <img
                  src={`data:image/png;base64,${offlineQRState.qrCode.qr_code_image}`}
                  alt="Offline QR Code"
                  style={{ maxWidth: '100%', marginTop: 16 }}
                />
              </Box>
            )}
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6">2. Verify Offline</Typography>

            <Button
              variant="contained"
              onClick={handleVerifyOfflineQR}
              disabled={offlineQRState.loading || !offlineQRState.qrCode}
              sx={{ mt: 2 }}
              fullWidth
            >
              Verify Offline QR
            </Button>

            {offlineQRState.verificationResult && (
              <Box sx={{ mt: 2 }}>
                <Chip
                  label={offlineQRState.verificationResult.verified ? 'VERIFIED' : 'FAILED'}
                  color={offlineQRState.verificationResult.verified ? 'success' : 'error'}
                  icon={offlineQRState.verificationResult.verified ? <VerifiedIcon /> : <ErrorIcon />}
                />

                <Accordion sx={{ mt: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>Verification Details</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List>
                      {offlineQRState.verificationResult.checks_performed?.map((check, index) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            {check.passed ? <VerifiedIcon color="success" /> : <ErrorIcon color="error" />}
                          </ListItemIcon>
                          <ListItemText primary={check.check_name} secondary={check.details} />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              </Box>
            )}
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderCertificateMonitoring = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Typography variant="h6" gutterBottom>
          Certificate Lifecycle Monitoring
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Monitor mDL Document Signer Certificate expiry and manage renewals.
        </Typography>
      </Grid>

      {certificateState.dashboard && (
        <>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6">Certificate Overview</Typography>
                <Grid container spacing={2} sx={{ mt: 1 }}>
                  <Grid item xs={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="primary">
                        {certificateState.dashboard.overview.total_certificates}
                      </Typography>
                      <Typography variant="body2">Total Certificates</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="error">
                        {certificateState.dashboard.overview.critical_alerts}
                      </Typography>
                      <Typography variant="body2">Critical Alerts</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="warning.main">
                        {certificateState.dashboard.overview.certificates_needing_renewal}
                      </Typography>
                      <Typography variant="body2">Need Renewal</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={3}>
                    <Box textAlign="center">
                      <Typography variant="h4" color="error">
                        {certificateState.dashboard.overview.expired_certificates}
                      </Typography>
                      <Typography variant="body2">Expired</Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6">Certificates</Typography>
                <List>
                  {certificateState.dashboard.certificates.map((cert) => (
                    <ListItem key={cert.certificate_id}>
                      <ListItemIcon>
                        {cert.status === 'expired' ? <ErrorIcon color="error" /> :
                         cert.status === 'critical' ? <WarningIcon color="error" /> :
                         cert.status === 'expiring_soon' ? <WarningIcon color="warning" /> :
                         <VerifiedIcon color="success" />}
                      </ListItemIcon>
                      <ListItemText
                        primary={cert.common_name}
                        secondary={`${cert.days_until_expiry} days until expiry • ${cert.status}`}
                      />
                      {cert.status !== 'active' && (
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => renewCertificate(cert.certificate_id)}
                        >
                          Renew
                        </Button>
                      )}
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </>
      )}
    </Grid>
  );

  const renderPolicyEngine = () => (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Typography variant="h6" gutterBottom>
          <PolicyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Policy-Based Selective Disclosure
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Context-aware attribute sharing using Marty's authorization engine.
        </Typography>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6">Available Policies</Typography>

            {policyState.policies && (
              <List>
                {Object.entries(policyState.policies.policies).map(([id, policy]) => (
                  <ListItem key={id}>
                    <ListItemText
                      primary={policy.name}
                      secondary={`${policy.context_type} • ${policy.purpose} • Privacy: ${policy.privacy_level}`}
                    />
                  </ListItem>
                ))}
              </List>
            )}

            <Button
              variant="outlined"
              onClick={loadPolicySummary}
              disabled={policyState.loading}
              fullWidth
              sx={{ mt: 2 }}
            >
              Reload Policies
            </Button>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6">Policy Evaluation</Typography>

            <Button
              variant="contained"
              onClick={evaluatePolicy}
              disabled={policyState.loading}
              fullWidth
              sx={{ mt: 2 }}
            >
              Evaluate Demo Policy
            </Button>

            {policyState.evaluation && (
              <Box sx={{ mt: 2 }}>
                <Chip
                  label={policyState.evaluation.recommended_action.replace('_', ' ').toUpperCase()}
                  color={policyState.evaluation.recommended_action === 'approve' ? 'success' : 'warning'}
                />

                <Accordion sx={{ mt: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>Evaluation Details</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <pre>{JSON.stringify(policyState.evaluation, null, 2)}</pre>
                  </AccordionDetails>
                </Accordion>
              </Box>
            )}
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Paper sx={{ p: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Enhanced mDoc/mDL Verifier Demo
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph>
          Explore advanced mDoc/mDL verification capabilities including age verification with selective disclosure,
          offline verification, certificate lifecycle management, and policy-based attribute sharing.
        </Typography>

        <Box sx={{ mb: 3 }}>
          <Button
            variant={selectedFeature === 'age-verification' ? 'contained' : 'outlined'}
            onClick={() => setSelectedFeature('age-verification')}
            sx={{ mr: 1, mb: 1 }}
          >
            Age Verification
          </Button>
          <Button
            variant={selectedFeature === 'offline-qr' ? 'contained' : 'outlined'}
            onClick={() => setSelectedFeature('offline-qr')}
            sx={{ mr: 1, mb: 1 }}
          >
            Offline QR
          </Button>
          <Button
            variant={selectedFeature === 'certificates' ? 'contained' : 'outlined'}
            onClick={() => setSelectedFeature('certificates')}
            sx={{ mr: 1, mb: 1 }}
          >
            Certificate Monitor
          </Button>
          <Button
            variant={selectedFeature === 'policy' ? 'contained' : 'outlined'}
            onClick={() => setSelectedFeature('policy')}
            sx={{ mr: 1, mb: 1 }}
          >
            Policy Engine
          </Button>
        </Box>

        {selectedFeature === 'age-verification' && renderAgeVerificationDemo()}
        {selectedFeature === 'offline-qr' && renderOfflineQRDemo()}
        {selectedFeature === 'certificates' && renderCertificateMonitoring()}
        {selectedFeature === 'policy' && renderPolicyEngine()}
      </Paper>
    </Container>
  );
};

export default EnhancedVerifierDemo;
