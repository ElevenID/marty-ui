/**
 * WalletSetup Component
 *
 * Allows users to set up their mobile wallet app:
 * 1. Display QR code for pairing
 * 2. Enable push notifications
 * 3. Show wallet connection status
 */

import { useState, useEffect, useCallback, useRef } from 'react';
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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import NotificationsIcon from '@mui/icons-material/Notifications';
import CheckIcon from '@mui/icons-material/Check';
import PhoneIcon from '@mui/icons-material/PhoneAndroid';
import RefreshIcon from '@mui/icons-material/Refresh';
import { QRCodeSVG } from 'qrcode.react';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';
import { usePermissions } from '../hooks/usePermissions';
import { useConsole } from '../contexts/ConsoleContext';
import { publicEntryHref } from '../application/routing/publicEntry';
import { listTrustProfiles } from '../services/presentationPolicyApi';
import {
  buildPairingState,
  formatCountdown,
  issueRemotePairingTicket,
  loadRemotePairingStatus,
  registerWalletPushNotifications,
  resolveNotificationPermissionState,
  resolveNotificationRequestOutcome,
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
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const { mode, activeOrgId } = useConsole();
  const { can, isLoading: permissionsLoading, error: permissionsError } = usePermissions();
  // State
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // QR code pairing state
  const [pairingCode, setPairingCode] = useState(null);
  const [pairingId, setPairingId] = useState(null);
  const [qrContent, setQrContent] = useState(null);
  const [expiresIn, setExpiresIn] = useState(300);
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [trustProfileId, setTrustProfileId] = useState('');
  const [verifierTrustProfileId, setVerifierTrustProfileId] = useState('');
  const [profileLoad, setProfileLoad] = useState({ organizationId: null, principalId: null, status: 'loading' });
  const [profileReload, setProfileReload] = useState(0);
  const pairingRequestId = useRef(0);
  const currentScope = useRef({ organizationId, principalId, trustProfileId, verifierTrustProfileId, profileReload });
  currentScope.current = { organizationId, principalId, trustProfileId, verifierTrustProfileId, profileReload };
  const hasProfileScope = Boolean(organizationId && principalId);
  const profileScopeCurrent = profileLoad.organizationId === organizationId && profileLoad.principalId === principalId;
  const profilesReady = hasProfileScope && profileScopeCurrent && profileLoad.status === 'ready';
  const profilesLoading = hasProfileScope && (!profileScopeCurrent || profileLoad.status === 'loading');
  const profilesFailed = hasProfileScope && profileScopeCurrent && profileLoad.status === 'error';
  const issuerProfiles = trustProfiles.filter((profile) => !Array.isArray(profile.trust_purposes)
    || profile.trust_purposes.includes('CREDENTIAL_ISSUER'));
  const canManageTrustProfiles = mode === 'org' && activeOrgId === organizationId && !permissionsLoading && !permissionsError
    && can('trust-profile', 'view')
    && (can('trust-profile', 'create') || can('trust-profile', 'edit') || can('trust-profile', 'activate'));

  // Wallet connection state
  const [walletConnected, setWalletConnected] = useState(false);
  const [walletDeviceId, setWalletDeviceId] = useState(null);

  // Notification state
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [notificationPermission, setNotificationPermission] = useState('default');

  const clearPairingPresentation = useCallback(() => {
    setPairingCode(null);
    setPairingId(null);
    setQrContent(null);
    setWalletConnected(false);
  }, []);

  const generatePairingCode = useCallback(async () => {
    if (!profilesReady || !trustProfileId) return;
    const requestId = ++pairingRequestId.current;
    const isCurrent = () => requestId === pairingRequestId.current &&
      currentScope.current.organizationId === organizationId &&
      currentScope.current.principalId === principalId &&
      currentScope.current.trustProfileId === trustProfileId &&
      currentScope.current.verifierTrustProfileId === verifierTrustProfileId;
    setLoading(true);
    setError(null);
    clearPairingPresentation();
    try {
      const ticket = await issueRemotePairingTicket({ organizationId, trustProfileId,
        ...(verifierTrustProfileId ? { verifierTrustProfileId } : {}) });
      const apiOrigin = new URL(import.meta.env.VITE_API_URL || window.location.origin, window.location.origin).origin;
      const nextPairingState = buildPairingState({
        pairingCode: ticket.pairing_code,
        pairingId: ticket.pairing_id,
        expiresAt: ticket.expires_at,
        apiOrigin,
      });
      if (!isCurrent()) return;
      setPairingCode(nextPairingState.pairingCode);
      setPairingId(nextPairingState.pairingId);
      setQrContent(nextPairingState.qrContent);
      setExpiresIn(nextPairingState.expiresIn);
    } catch (err) {
      if (isCurrent()) setError(err.message || 'Could not issue a wallet pairing code');
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [organizationId, principalId, trustProfileId, verifierTrustProfileId, profilesReady, clearPairingPresentation]);

  const reloadProfiles = () => {
    pairingRequestId.current += 1;
    setLoading(false);
    clearPairingPresentation();
    setProfileLoad({ organizationId, principalId, status: 'loading' });
    setProfileReload((value) => value + 1);
  };

  useEffect(() => {
    let current = true;
    const isCurrent = () => current && currentScope.current.organizationId === organizationId
      && currentScope.current.principalId === principalId && currentScope.current.profileReload === profileReload;
    pairingRequestId.current += 1;
    setLoading(false);
    setTrustProfiles([]);
    setTrustProfileId('');
    setVerifierTrustProfileId('');
    setProfileLoad({ organizationId, principalId, status: organizationId && principalId ? 'loading' : 'idle' });
    clearPairingPresentation();
    setActiveStep(0);
    setWalletDeviceId(null);
    setSuccess(null);
    setError(null);
    if (organizationId && principalId) {
      listTrustProfiles({ organization_id: organizationId })
        .then((profiles) => {
          if (!isCurrent()) return;
          const eligible = profiles.filter((profile) => profile.status === 'active');
          setTrustProfiles(eligible);
          setProfileLoad({ organizationId, principalId, status: 'ready' });
          const issuers = eligible.filter((profile) => !Array.isArray(profile.trust_purposes)
            || profile.trust_purposes.includes('CREDENTIAL_ISSUER'));
          if (issuers.length === 1) setTrustProfileId(issuers[0].id);
        })
        .catch(() => { if (isCurrent()) setProfileLoad({ organizationId, principalId, status: 'error' }); });
    }
    return () => { current = false; };
  }, [organizationId, principalId, profileReload, clearPairingPresentation]);

  const checkWalletStatus = useCallback(async () => {
    if (!pairingId || activeStep !== 0) return;
    const requestId = pairingRequestId.current;
    const { organizationId: requestOrganizationId, principalId: requestPrincipalId, trustProfileId: requestTrustProfileId,
      verifierTrustProfileId: requestVerifierProfileId } = currentScope.current;
    const isCurrent = () => requestId === pairingRequestId.current &&
      currentScope.current.organizationId === requestOrganizationId &&
      currentScope.current.principalId === requestPrincipalId &&
      currentScope.current.trustProfileId === requestTrustProfileId &&
      currentScope.current.verifierTrustProfileId === requestVerifierProfileId;
    try {
      const status = await loadRemotePairingStatus({ pairingId });
      if (!isCurrent()) return;
      if (status.state === 'paired' && status.registration_id) {
        setWalletConnected(true);
        setWalletDeviceId(status.registration_id);
        setActiveStep(1);
        setSuccess('Wallet paired successfully!');
      } else if (status.state === 'expired') {
        setError('Pairing expired. Refresh the QR code and try again.');
        setPairingId(null);
      }
    } catch (err) {
      if (isCurrent()) {
        setError(err.message || 'Could not check wallet pairing status');
      }
    }
  }, [pairingId, activeStep]);

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

  // Generate a ticket only after the user has an organization-scoped profile.
  useEffect(() => {
    checkNotificationPermission();
  }, [checkNotificationPermission]);

  useEffect(() => {
    if (trustProfileId && profilesReady) generatePairingCode();
  }, [trustProfileId, profilesReady, generatePairingCode]);

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
      if (pairingId && shouldPollWalletStatus({ activeStep, walletConnected })) {
        await checkWalletStatus();
      }
    }, walletSetupDefaults.pollIntervalMs);
    return () => clearInterval(pollInterval);
  }, [activeStep, walletConnected, pairingId, checkWalletStatus]);

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
                Choose an active issuer Trust Profile, then scan the pairing code with the {branding.authenticatorName} app.
              </Typography>

              {!hasProfileScope && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography>Select an organization to load wallet Trust Profiles.</Typography>
                  <Button component="a" href={publicEntryHref('/console/organizations')} sx={{ mt: 1 }}>
                    Open my organizations
                  </Button>
                </Alert>
              )}
              {profilesLoading && (
                <Box role="status" sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <CircularProgress size={20} />
                  <Typography>Loading Trust Profiles…</Typography>
                </Box>
              )}
              {profilesFailed && (
                <Alert severity="error" sx={{ mb: 2 }} data-testid="wallet-profiles-error">
                  Could not load Trust Profiles for wallet pairing. Reload profiles to try again.
                </Alert>
              )}
              {profilesReady && issuerProfiles.length === 0 && (
                <Alert severity="info" sx={{ mb: 2 }} data-testid="wallet-profiles-empty">
                  <Typography>No active issuer Trust Profiles are available for this organization.</Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    {canManageTrustProfiles
                      ? 'Configure and activate a credential issuer Trust Profile, then reload profiles here to pair your wallet.'
                      : 'Open your organizations to select this organization and check your access, or ask its administrator to activate an issuer Trust Profile. Then return here and reload profiles.'}
                  </Typography>
                  <Button
                    component="a"
                    href={publicEntryHref(canManageTrustProfiles ? '/console/org/trust/profiles' : '/console/organizations')}
                    sx={{ mt: 1 }}
                  >
                    {canManageTrustProfiles ? 'Set up Trust Profiles' : 'Open my organizations'}
                  </Button>
                </Alert>
              )}

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel id="wallet-trust-profile-label">Trust Profile</InputLabel>
                <Select
                  labelId="wallet-trust-profile-label"
                  label="Trust Profile"
                  value={profilesReady ? trustProfileId : ''}
                  disabled={!profilesReady || issuerProfiles.length === 0}
                  onChange={(event) => {
                    pairingRequestId.current += 1;
                    setLoading(false);
                    clearPairingPresentation();
                    setTrustProfileId(event.target.value);
                    if (event.target.value === verifierTrustProfileId) setVerifierTrustProfileId('');
                  }}
                  data-testid="wallet-trust-profile-select"
                >
                  {profilesReady && issuerProfiles.map((profile) => (
                    <MenuItem key={profile.id} value={profile.id}>{profile.name || profile.id}</MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl fullWidth sx={{ mb: 1 }}>
                <InputLabel id="wallet-verifier-profile-label">Verifier Trust Profile (optional)</InputLabel>
                <Select
                  labelId="wallet-verifier-profile-label"
                  label="Verifier Trust Profile (optional)"
                  value={profilesReady ? verifierTrustProfileId : ''}
                  disabled={!profilesReady || issuerProfiles.length === 0}
                  onChange={(event) => {
                    pairingRequestId.current += 1;
                    setLoading(false);
                    clearPairingPresentation();
                    setVerifierTrustProfileId(event.target.value);
                  }}
                  data-testid="wallet-verifier-profile-select"
                >
                  <MenuItem value="">No verifier profile selected</MenuItem>
                  {profilesReady && trustProfiles.filter((profile) => profile.id !== trustProfileId
                    && Array.isArray(profile.trust_purposes)
                    && profile.trust_purposes.includes('PRESENTATION_VERIFIER')).map((profile) => (
                    <MenuItem key={profile.id} value={profile.id}>{profile.name || profile.id}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Choose the trust profile used to authenticate presentation requests to your wallet.
              </Typography>

              {profilesReady && issuerProfiles.length > 0 && <Card sx={{ maxWidth: 320, mx: 'auto', mb: 2 }}>
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
                    <Typography color="text.secondary">Select an active Trust Profile to generate a pairing code.</Typography>
                  )}
                </CardContent>
              </Card>}

              <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={reloadProfiles}
                  disabled={!hasProfileScope || profilesLoading}
                >
                  Reload profiles
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={generatePairingCode}
                  disabled={loading || !trustProfileId || !profilesReady}
                  data-testid="refresh-qr-button"
                >
                  Refresh QR
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
                  Wallet registration ID: <code data-testid="wallet-device-id">{walletDeviceId || 'Connected'}</code>
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
