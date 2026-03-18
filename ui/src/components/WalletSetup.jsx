/**
 * WalletSetup Component
 *
 * Allows users to set up their mobile wallet app:
 * 1. Display QR code for pairing
 * 2. Enable push notifications
 * 3. Show wallet connection status
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Alert,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Card,
  CardContent,
  CircularProgress,
  Switch,
  FormControlLabel,
  Divider,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Check as CheckIcon,
  PhoneAndroid as PhoneIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { QRCodeSVG } from 'qrcode.react';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';
import {
  buildPairingState,
  createPairingCode,
  formatCountdown,
  loadWalletStatus,
  registerWalletPushNotifications,
  resolveNotificationPermissionState,
  resolveNotificationRequestOutcome,
  resolveSimulatedPairing,
  resolveSkipNotifications,
  resolveWalletSetupComplete,
  shouldPollWalletStatus,
  shouldTickPairingCountdown,
  walletSetupDefaults,
} from '../application/wallet';

/**
 * WalletSetup Component
 */
const WalletSetup = () => {
  const branding = useBranding();
  const { user, organizationId } = useAuth();
  // State
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // QR code pairing state
  const [pairingCode, setPairingCode] = useState(null);
  const [qrContent, setQrContent] = useState(null);
  const [expiresIn, setExpiresIn] = useState(300);

  // Wallet connection state
  const [walletConnected, setWalletConnected] = useState(false);
  const [walletDeviceId, setWalletDeviceId] = useState(null);

  // Notification state
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [notificationPermission, setNotificationPermission] = useState('default');

  const generatePairingCode = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const nextPairingCode = createPairingCode();
      const nextPairingState = buildPairingState({
        deepLinkProtocol: branding.deepLinkProtocol,
        pairingCode: nextPairingCode,
      });
      setPairingCode(nextPairingState.pairingCode);
      setQrContent(nextPairingState.qrContent);
      setExpiresIn(nextPairingState.expiresIn);
    } finally {
      setLoading(false);
    }
  }, [branding]);

  const checkWalletStatus = useCallback(async () => {
    const nextState = await loadWalletStatus({
      userId: user?.user_id,
      activeStep,
    });

    if (nextState.walletConnected) {
      setWalletConnected(nextState.walletConnected);
      setWalletDeviceId(nextState.walletDeviceId);
      if (nextState.nextStep !== null) {
        setActiveStep(nextState.nextStep);
      }
      if (nextState.successMessage) {
        setSuccess(nextState.successMessage);
      }
    }
  }, [user, activeStep]);

  const checkNotificationPermission = useCallback(() => {
    if ('Notification' in window) {
      const nextPermissionState = resolveNotificationPermissionState(Notification.permission);
      setNotificationPermission(nextPermissionState.notificationPermission);
      setNotificationsEnabled(nextPermissionState.notificationsEnabled);
    }
  }, []);

  const registerPushNotifications = useCallback(async () => {
    const result = await registerWalletPushNotifications({
      userId: user?.user_id,
      organizationId,
      storage: window.localStorage,
    });

    if (result.deviceId) {
      setWalletDeviceId(result.deviceId);
    }
  }, [user, organizationId]);

  const skipNotifications = useCallback(() => {
    const outcome = resolveSkipNotifications();
    setActiveStep(outcome.nextStep);
    setSuccess(outcome.successMessage);
  }, []);

  const handleComplete = useCallback(() => {
    setSuccess(resolveWalletSetupComplete().successMessage);
  }, []);

  // Generate pairing code on mount
  useEffect(() => {
    generatePairingCode();
    checkWalletStatus();
    checkNotificationPermission();
  }, [generatePairingCode, checkWalletStatus, checkNotificationPermission]);

  // Countdown timer for QR code expiry
  useEffect(() => {
    if (shouldTickPairingCountdown({ expiresIn, pairingCode })) {
      const timer = setTimeout(() => setExpiresIn(expiresIn - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [expiresIn, pairingCode]);

  // Poll for wallet connection status
  useEffect(() => {
    const pollInterval = setInterval(async () => {
      if (shouldPollWalletStatus({ activeStep, walletConnected })) {
        await checkWalletStatus();
      }
    }, walletSetupDefaults.pollIntervalMs);
    return () => clearInterval(pollInterval);
  }, [activeStep, walletConnected, checkWalletStatus]);

  const requestNotificationPermission = async () => {
    setLoading(true);
    setError(null);

    try {
      if (!('Notification' in window)) {
        throw new Error('Notifications not supported in this browser');
      }

      const permission = await Notification.requestPermission();
      const nextPermissionState = resolveNotificationPermissionState(permission);
      const outcome = resolveNotificationRequestOutcome(permission);
      setNotificationPermission(nextPermissionState.notificationPermission);
      setNotificationsEnabled(nextPermissionState.notificationsEnabled);

      if (permission === 'granted') {
        // Register for push notifications with backend
        await registerPushNotifications();
      }

      if (outcome.successMessage) {
        setSuccess(outcome.successMessage);
      }
      if (outcome.errorMessage) {
        setError(outcome.errorMessage);
      }
      if (outcome.nextStep !== null) {
        setActiveStep(outcome.nextStep);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };


  return (
    <Container maxWidth="md" data-testid="wallet-setup-page">
      <Paper sx={{ p: 4, mt: 4 }}>
        <Typography variant="h4" gutterBottom data-testid="wallet-setup-title">
          <PhoneIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Set Up Mobile Wallet
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph>
          Connect your mobile wallet app to receive credentials and notifications.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }} data-testid="wallet-setup-error">
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 2 }} data-testid="wallet-setup-success">
            {success}
          </Alert>
        )}

        <Stepper activeStep={activeStep} orientation="vertical">
          {/* Step 1: Scan QR Code */}
          <Step>
            <StepLabel data-testid="step-scan-qr">
              <Typography variant="h6">Scan QR Code</Typography>
            </StepLabel>
            <StepContent>
              <Typography color="text.secondary" paragraph>
                Open the {branding.authenticatorName} app and scan this QR code to pair your wallet.
              </Typography>

              <Card sx={{ maxWidth: 320, mx: 'auto', mb: 2 }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  {loading ? (
                    <CircularProgress data-testid="qr-loading" />
                  ) : qrContent ? (
                    <Box data-testid="pairing-qr-code" data-value={qrContent}>
                      <QRCodeSVG
                        value={qrContent}
                        size={200}
                        level="M"
                        includeMargin
                        data-testid="qr-code"
                      />
                      <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                        Code: <strong data-testid="pairing-code">{pairingCode}</strong>
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Expires in: <span data-testid="qr-expires-in">{formatCountdown(expiresIn)}</span>
                      </Typography>
                    </Box>
                  ) : (
                    <Typography color="error">Failed to generate QR code</Typography>
                  )}
                </CardContent>
              </Card>

              <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={generatePairingCode}
                  disabled={loading}
                  data-testid="refresh-qr-button"
                >
                  Refresh QR
                </Button>
                <Button
                  variant="contained"
                  onClick={() => {
                    // For testing: simulate successful pairing
                    const nextState = resolveSimulatedPairing();
                    setWalletConnected(nextState.walletConnected);
                    setActiveStep(nextState.nextStep);
                    setSuccess(nextState.successMessage);
                  }}
                  data-testid="simulate-pairing-button"
                >
                  Simulate Pairing
                </Button>
              </Box>

              {walletConnected && (
                <Alert severity="success" sx={{ mt: 2 }} data-testid="wallet-connected-alert">
                  <CheckIcon sx={{ mr: 1 }} />
                  Wallet connected!
                </Alert>
              )}
            </StepContent>
          </Step>

          {/* Step 2: Enable Notifications */}
          <Step>
            <StepLabel data-testid="step-enable-notifications">
              <Typography variant="h6">Enable Notifications</Typography>
            </StepLabel>
            <StepContent>
              <Typography color="text.secondary" paragraph>
                Enable push notifications to receive alerts about new credentials and important updates.
              </Typography>

              <Card sx={{ mb: 2 }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <NotificationsIcon color="primary" fontSize="large" />
                    <Box sx={{ flexGrow: 1 }}>
                      <Typography variant="subtitle1">Push Notifications</Typography>
                      <Typography variant="body2" color="text.secondary">
                        Receive real-time alerts for credential offers and verification requests
                      </Typography>
                    </Box>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={notificationsEnabled}
                          onChange={requestNotificationPermission}
                          disabled={loading || notificationPermission === 'denied'}
                          data-testid="notifications-toggle"
                        />
                      }
                      label={notificationsEnabled ? 'Enabled' : 'Disabled'}
                      labelPlacement="start"
                    />
                  </Box>

                  {notificationPermission === 'denied' && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      Notifications are blocked. Please enable them in your browser settings.
                    </Alert>
                  )}
                </CardContent>
              </Card>

              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button
                  variant="contained"
                  onClick={requestNotificationPermission}
                  disabled={loading || notificationsEnabled}
                  startIcon={<NotificationsIcon />}
                  data-testid="enable-notifications-button"
                >
                  {loading ? 'Enabling...' : 'Enable Notifications'}
                </Button>
                <Button
                  variant="outlined"
                  onClick={skipNotifications}
                  data-testid="skip-notifications-button"
                >
                  Skip for Now
                </Button>
              </Box>
            </StepContent>
          </Step>

          {/* Step 3: Complete */}
          <Step>
            <StepLabel data-testid="step-complete">
              <Typography variant="h6">Setup Complete</Typography>
            </StepLabel>
            <StepContent>
              <Alert severity="success" sx={{ mb: 2 }} data-testid="setup-complete-alert">
                <Typography variant="subtitle1">
                  Your wallet is ready to use!
                </Typography>
              </Alert>

              <Typography paragraph>
                You can now:
              </Typography>
              <Box component="ul" sx={{ mb: 2 }}>
                <li>Receive credentials from issuers</li>
                <li>Present credentials for verification</li>
                {notificationsEnabled && <li>Get notified about important events</li>}
              </Box>

              <Divider sx={{ my: 2 }} />

              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                <CheckIcon color="success" />
                <Typography>
                  Wallet ID: <code data-testid="wallet-device-id">{walletDeviceId || 'Connected'}</code>
                </Typography>
              </Box>

              <Button
                variant="contained"
                color="primary"
                onClick={handleComplete}
                sx={{ mt: 3 }}
                data-testid="finish-setup-button"
              >
                Finish Setup
              </Button>
            </StepContent>
          </Step>
        </Stepper>
      </Paper>
    </Container>
  );
};

export default WalletSetup;
