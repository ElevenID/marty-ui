/**
 * Wallet Pairing Step Component
 * 
 * Step for Applicants to pair their Marty Authenticator app
 * during the onboarding flow.
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Paper,
  Fade,
  CircularProgress,
  Alert,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Link,
  Divider,
} from '@mui/material';
import QrCodeIcon from '@mui/icons-material/QrCode';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DownloadIcon from '@mui/icons-material/Download';
import SkipNextIcon from '@mui/icons-material/SkipNext';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

const WalletPairingStep = ({
  onPairingComplete,
  onSkip,
  submitting,
}) => {
  const [pairingStep, setPairingStep] = useState(0);
  const [qrCode, setQrCode] = useState(null);
  const [pairingToken, setPairingToken] = useState(null);
  const [pairingStatus, setPairingStatus] = useState('pending'); // 'pending' | 'scanning' | 'paired' | 'error'
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // Poll for pairing status when QR code is displayed
  useEffect(() => {
    let pollInterval;
    
    if (pairingToken && pairingStatus === 'scanning') {
      pollInterval = setInterval(async () => {
        try {
          const response = await fetch(
            `${API_BASE_URL}/wallet/pairing/${pairingToken}/status`,
            { credentials: 'include' }
          );
          
          if (response.ok) {
            const data = await response.json();
            if (data.status === 'paired') {
              setPairingStatus('paired');
              clearInterval(pollInterval);
              setTimeout(() => {
                onPairingComplete(data);
              }, 2000);
            }
          }
        } catch (err) {
          console.error('Error polling pairing status:', err);
        }
      }, 2000);
    }
    
    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [pairingToken, pairingStatus, onPairingComplete]);

  const generatePairingQR = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE_URL}/wallet/pairing/generate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate pairing code');
      }
      
      const data = await response.json();
      setQrCode(data.qr_code_data_url || data.qr_code);
      setPairingToken(data.pairing_token);
      setPairingStatus('scanning');
      setPairingStep(2);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadApp = () => {
    setPairingStep(1);
  };

  const handleHaveApp = () => {
    generatePairingQR();
  };

  return (
    <Fade in>
      <Box data-testid="wallet-pairing-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Connect Your Marty Authenticator
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          Pair your mobile wallet to receive and store digital credentials
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {pairingStatus === 'paired' ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <CheckCircleIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
            <Typography variant="h5" color="success.main" gutterBottom>
              Wallet Paired Successfully!
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Your Marty Authenticator is now connected.
            </Typography>
          </Box>
        ) : (
          <Box sx={{ maxWidth: 600, mx: 'auto' }}>
            <Stepper activeStep={pairingStep} orientation="vertical">
              {/* Step 1: Get the app */}
              <Step>
                <StepLabel>
                  <Typography fontWeight="medium">Get the Marty Authenticator App</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Download the Marty Authenticator app from your device's app store.
                  </Typography>
                  
                  <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
                    <Button
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      component={Link}
                      href="https://apps.apple.com/app/marty-authenticator"
                      target="_blank"
                      rel="noopener"
                    >
                      App Store
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      component={Link}
                      href="https://play.google.com/store/apps/details?id=com.marty.authenticator"
                      target="_blank"
                      rel="noopener"
                    >
                      Google Play
                    </Button>
                  </Box>
                  
                  <Divider sx={{ my: 2 }} />
                  
                  <Box sx={{ display: 'flex', gap: 2 }}>
                    <Button
                      variant="contained"
                      onClick={handleHaveApp}
                      startIcon={<PhoneAndroidIcon />}
                      data-testid="have-app-btn"
                    >
                      I have the app
                    </Button>
                    <Button
                      onClick={handleDownloadApp}
                      data-testid="download-app-btn"
                    >
                      Download first
                    </Button>
                  </Box>
                </StepContent>
              </Step>

              {/* Step 2: Download */}
              <Step>
                <StepLabel>
                  <Typography fontWeight="medium">Download & Install</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Open the app after installation and complete the initial setup.
                    Then tap "Pair with Organization" in the app.
                  </Typography>
                  <Button
                    variant="contained"
                    onClick={handleHaveApp}
                    startIcon={<PhoneAndroidIcon />}
                    data-testid="ready-to-pair-btn"
                  >
                    Ready to Pair
                  </Button>
                </StepContent>
              </Step>

              {/* Step 3: Scan QR */}
              <Step>
                <StepLabel>
                  <Typography fontWeight="medium">Scan QR Code</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Open the Marty Authenticator app and scan this QR code to pair.
                  </Typography>
                  
                  {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                      <CircularProgress />
                    </Box>
                  ) : qrCode ? (
                    <Paper
                      variant="outlined"
                      sx={{
                        p: 3,
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        bgcolor: 'white',
                        maxWidth: 280,
                        mx: 'auto',
                      }}
                      data-testid="pairing-qr-container"
                    >
                      <img
                        src={qrCode}
                        alt="Pairing QR Code"
                        style={{ width: 200, height: 200 }}
                        data-testid="pairing-qr-code"
                        data-value={pairingToken}
                      />
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 2 }}>
                        Waiting for you to scan...
                      </Typography>
                      <CircularProgress size={20} sx={{ mt: 1 }} />
                    </Paper>
                  ) : (
                    <Button
                      variant="contained"
                      onClick={generatePairingQR}
                      startIcon={<QrCodeIcon />}
                      data-testid="generate-pairing-qr-btn"
                    >
                      Generate QR Code
                    </Button>
                  )}
                </StepContent>
              </Step>
            </Stepper>

            {/* Skip option */}
            <Box sx={{ mt: 4, textAlign: 'center' }}>
              <Button
                variant="text"
                color="inherit"
                onClick={onSkip}
                startIcon={<SkipNextIcon />}
                disabled={submitting}
                data-testid="skip-wallet-pairing-btn"
              >
                Skip for now
              </Button>
              <Typography variant="caption" display="block" color="text.secondary">
                You can pair your wallet later from your dashboard
              </Typography>
            </Box>
          </Box>
        )}
      </Box>
    </Fade>
  );
};

export default WalletPairingStep;
