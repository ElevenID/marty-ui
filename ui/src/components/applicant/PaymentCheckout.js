/**
 * PaymentCheckout Component
 * 
 * Handles processing fee payment for credential applications.
 * Integrates with PaymentContext for Square Web Payments SDK.
 */

import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Button,
  Stepper,
  Step,
  StepLabel,
  Grid,
  Card,
  CardContent,
  Divider,
  TextField,
  FormControlLabel,
  Checkbox,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip
} from '@mui/material';
import {
  Payment as PaymentIcon,
  CheckCircle as SuccessIcon,
  CreditCard as CardIcon,
  Receipt as ReceiptIcon,
  Security as SecurityIcon,
  Schedule as TimeIcon,
  Description as DocumentIcon
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { usePayment } from '../../contexts/PaymentContext';

const STEPS = ['Review Application', 'Payment Details', 'Confirmation'];

const PaymentCheckout = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, organizationName } = useAuth();
  const { 
    initializePayment, 
    processPayment, 
    isProcessing, 
    error: paymentError,
    isMockMode
  } = usePayment();
  
  // Get credential info from navigation state
  const credential = location.state?.credential;
  const processingFee = location.state?.processingFee || 0;
  
  // State
  const [activeStep, setActiveStep] = useState(0);
  const [paymentCard, setPaymentCard] = useState(null);
  const [agreeToTerms, setAgreeToTerms] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [paymentComplete, setPaymentComplete] = useState(false);
  const [receiptData, setReceiptData] = useState(null);
  
  // Billing information
  const [billingInfo, setBillingInfo] = useState({
    name: user?.name || '',
    email: user?.email || '',
    address: '',
    city: '',
    state: '',
    zip: '',
    country: 'US'
  });

  useEffect(() => {
    if (!credential) {
      // Redirect if no credential context
      navigate('/credentials');
      return;
    }
    
    // Initialize Square payment form
    if (processingFee > 0) {
      initSquarePayment();
    }
  }, [credential, processingFee]);

  /**
   * Initialize Square Web Payments SDK
   */
  const initSquarePayment = async () => {
    try {
      const payments = await initializePayment();
      if (payments) {
        const card = await payments.card();
        await card.attach('#card-container');
        setPaymentCard(card);
      }
    } catch (err) {
      console.error('Failed to initialize payment:', err);
      setError('Failed to load payment form. Please refresh and try again.');
    }
  };

  /**
   * Handle billing info change
   */
  const handleBillingChange = (field) => (event) => {
    setBillingInfo(prev => ({
      ...prev,
      [field]: event.target.value
    }));
  };

  /**
   * Validate billing information
   */
  const validateBilling = () => {
    const required = ['name', 'email', 'address', 'city', 'state', 'zip'];
    return required.every(field => billingInfo[field]?.trim());
  };

  /**
   * Handle step navigation
   */
  const handleNext = () => {
    if (activeStep === 0) {
      // Move to payment step
      setActiveStep(1);
    } else if (activeStep === 1) {
      // Process payment
      handlePayment();
    }
  };

  const handleBack = () => {
    setActiveStep(prev => prev - 1);
  };

  /**
   * Process the payment
   */
  const handlePayment = async () => {
    if (processingFee === 0) {
      // No payment needed, submit application directly
      await submitApplication(null);
      return;
    }

    if (!paymentCard && !isMockMode) {
      setError('Payment form not initialized');
      return;
    }

    if (!validateBilling()) {
      setError('Please complete all billing information');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Tokenize the card (or use mock)
      let token;
      if (isMockMode) {
        token = 'mock-payment-token-' + Date.now();
      } else {
        const tokenResult = await paymentCard.tokenize();
        if (tokenResult.status !== 'OK') {
          throw new Error(tokenResult.errors?.[0]?.message || 'Card tokenization failed');
        }
        token = tokenResult.token;
      }

      // Process the payment
      const paymentResult = await processPayment({
        token,
        amount: processingFee * 100, // Convert to cents
        currency: 'USD',
        billingContact: billingInfo,
        metadata: {
          credentialId: credential.id,
          credentialName: credential.name,
          applicantEmail: user?.email
        }
      });

      if (paymentResult.success) {
        // Submit the application with payment confirmation
        await submitApplication(paymentResult);
      } else {
        throw new Error(paymentResult.error || 'Payment failed');
      }
    } catch (err) {
      console.error('Payment error:', err);
      setError(err.message || 'Payment processing failed');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Submit the credential application
   */
  const submitApplication = async (paymentResult) => {
    try {
      const response = await fetch('/api/applicant/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId: credential.id,
          credentialType: credential.id,
          paymentId: paymentResult?.paymentId,
          processingFee: processingFee,
          billingInfo: billingInfo
        })
      });

      if (response.ok) {
        const result = await response.json();
        setReceiptData({
          applicationId: result.applicationId,
          paymentId: paymentResult?.paymentId,
          amount: processingFee,
          date: new Date().toISOString(),
          credentialName: credential.name
        });
        setPaymentComplete(true);
        setActiveStep(2);
      } else {
        throw new Error('Failed to submit application');
      }
    } catch (err) {
      console.error('Application submission error:', err);
      // If payment succeeded but application failed, still show success
      // The backend should handle reconciliation
      setReceiptData({
        paymentId: paymentResult?.paymentId,
        amount: processingFee,
        date: new Date().toISOString(),
        credentialName: credential.name,
        warning: 'Application submission pending - you will receive a confirmation email'
      });
      setPaymentComplete(true);
      setActiveStep(2);
    }
  };

  /**
   * Render step content
   */
  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return renderReviewStep();
      case 1:
        return renderPaymentStep();
      case 2:
        return renderConfirmationStep();
      default:
        return null;
    }
  };

  /**
   * Step 1: Review Application
   */
  const renderReviewStep = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={8}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              <DocumentIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Credential Details
            </Typography>
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Credential Type
              </Typography>
              <Typography variant="body1">{credential?.name}</Typography>
            </Box>
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Description
              </Typography>
              <Typography variant="body1">{credential?.description}</Typography>
            </Box>
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Vendor
              </Typography>
              <Typography variant="body1">{organizationName || credential?.vendorName}</Typography>
            </Box>
            
            <Box>
              <Typography variant="subtitle2" color="text.secondary">
                Processing Time
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TimeIcon fontSize="small" color="action" />
                <Typography variant="body1">{credential?.processingTime}</Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Grid>
      
      <Grid item xs={12} md={4}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              <ReceiptIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Order Summary
            </Typography>
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography>Application Fee</Typography>
              <Typography>${processingFee.toFixed(2)}</Typography>
            </Box>
            
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="h6">Total</Typography>
              <Typography variant="h6">${processingFee.toFixed(2)}</Typography>
            </Box>
            
            {processingFee === 0 && (
              <Alert severity="success" sx={{ mt: 2 }}>
                No payment required for this credential
              </Alert>
            )}
          </CardContent>
        </Card>
        
        <Box sx={{ mt: 2 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={agreeToTerms}
                onChange={(e) => setAgreeToTerms(e.target.checked)}
              />
            }
            label={
              <Typography variant="body2">
                I agree to the Terms of Service and Privacy Policy
              </Typography>
            }
          />
        </Box>
      </Grid>
    </Grid>
  );

  /**
   * Step 2: Payment Details
   */
  const renderPaymentStep = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={7}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              <CardIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Billing Information
            </Typography>
            <Divider sx={{ my: 2 }} />
            
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Full Name"
                  value={billingInfo.name}
                  onChange={handleBillingChange('name')}
                  required
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Email"
                  type="email"
                  value={billingInfo.email}
                  onChange={handleBillingChange('email')}
                  required
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Address"
                  value={billingInfo.address}
                  onChange={handleBillingChange('address')}
                  required
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="City"
                  value={billingInfo.city}
                  onChange={handleBillingChange('city')}
                  required
                />
              </Grid>
              <Grid item xs={3}>
                <TextField
                  fullWidth
                  label="State"
                  value={billingInfo.state}
                  onChange={handleBillingChange('state')}
                  required
                />
              </Grid>
              <Grid item xs={3}>
                <TextField
                  fullWidth
                  label="ZIP"
                  value={billingInfo.zip}
                  onChange={handleBillingChange('zip')}
                  required
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
        
        {processingFee > 0 && (
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <PaymentIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Payment Method
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              {isMockMode && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <strong>Test Mode:</strong> No real charges will be made.
                  Use any test card number.
                </Alert>
              )}
              
              {/* Square Card Container */}
              <Box 
                id="card-container" 
                sx={{ 
                  minHeight: 100,
                  p: 2,
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 1
                }}
              />
              
              <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon fontSize="small" color="action" />
                <Typography variant="caption" color="text.secondary">
                  Your payment is secured with SSL encryption
                </Typography>
              </Box>
            </CardContent>
          </Card>
        )}
      </Grid>
      
      <Grid item xs={12} md={5}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              <ReceiptIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Order Summary
            </Typography>
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" color="text.secondary">
                {credential?.name}
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography>Processing Fee</Typography>
              <Typography>${processingFee.toFixed(2)}</Typography>
            </Box>
            
            <Divider sx={{ my: 2 }} />
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="h6">Total</Typography>
              <Typography variant="h6" color="primary">
                ${processingFee.toFixed(2)}
              </Typography>
            </Box>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  /**
   * Step 3: Confirmation
   */
  const renderConfirmationStep = () => (
    <Box sx={{ textAlign: 'center', py: 4 }}>
      <SuccessIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
      <Typography variant="h4" gutterBottom>
        Application Submitted!
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Your application for {receiptData?.credentialName} has been successfully submitted.
      </Typography>
      
      {receiptData?.warning && (
        <Alert severity="warning" sx={{ maxWidth: 500, mx: 'auto', mb: 3 }}>
          {receiptData.warning}
        </Alert>
      )}
      
      <Card sx={{ maxWidth: 400, mx: 'auto', mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Receipt
          </Typography>
          <Divider sx={{ my: 2 }} />
          <List dense>
            {receiptData?.applicationId && (
              <ListItem>
                <ListItemText 
                  primary="Application ID"
                  secondary={receiptData.applicationId}
                />
              </ListItem>
            )}
            {receiptData?.paymentId && (
              <ListItem>
                <ListItemText 
                  primary="Payment ID"
                  secondary={receiptData.paymentId}
                />
              </ListItem>
            )}
            <ListItem>
              <ListItemText 
                primary="Amount Paid"
                secondary={`$${receiptData?.amount?.toFixed(2) || '0.00'}`}
              />
            </ListItem>
            <ListItem>
              <ListItemText 
                primary="Date"
                secondary={new Date(receiptData?.date).toLocaleString()}
              />
            </ListItem>
          </List>
        </CardContent>
      </Card>
      
      <Typography variant="body2" color="text.secondary" paragraph>
        A confirmation email has been sent to {user?.email}
      </Typography>
      
      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
        <Button variant="outlined" onClick={() => navigate('/my-applications')}>
          View My Applications
        </Button>
        <Button variant="contained" onClick={() => navigate('/credentials')}>
          Browse More Credentials
        </Button>
      </Box>
    </Box>
  );

  if (!credential) {
    return null;
  }

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <PaymentIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          Complete Your Application
        </Typography>
      </Box>

      <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
        {STEPS.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {(error || paymentError) && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error || paymentError}
        </Alert>
      )}

      <Paper sx={{ p: 3 }}>
        {renderStepContent(activeStep)}
        
        {activeStep < 2 && (
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4, pt: 2, borderTop: 1, borderColor: 'divider' }}>
            <Button
              disabled={activeStep === 0}
              onClick={handleBack}
            >
              Back
            </Button>
            <Button
              variant="contained"
              onClick={handleNext}
              disabled={
                (activeStep === 0 && !agreeToTerms) || 
                (activeStep === 1 && !validateBilling()) ||
                loading || 
                isProcessing
              }
              startIcon={loading || isProcessing ? <CircularProgress size={20} /> : null}
            >
              {activeStep === 0 
                ? 'Continue to Payment' 
                : processingFee > 0 
                  ? `Pay $${processingFee.toFixed(2)}`
                  : 'Submit Application'
              }
            </Button>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default PaymentCheckout;
