/**
 * Onboarding Page Component
 *
 * Post-registration onboarding flow where users:
 * 1. Choose their role (Applicant or Vendor)
 * 2. For Applicants: Join via invite code, request membership, or select open org
 * 3. For Vendors: Create a new organization with visibility/membership settings
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Container,
  CircularProgress,
  Alert,
  Paper,
  Fade,
  Link,
} from '@mui/material';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ScheduleIcon from '@mui/icons-material/Schedule';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';

import {
  RoleSelectionStep,
  ApplicantJoinStep,
  VendorCreateOrgStep,
  CompletionStep,
  ConfirmOrgDialog,
  WalletPairingStep,
  TrustProfileStep,
  VerifierIdentityStep,
  IssuerIdentityStep,
  TrustSourcesStep,
  TrustHealthCheckStep,
  BusinessContextStep,
  TechnicalIdentityStep,
} from './onboarding';
import UseCaseStep from './onboarding/steps/UseCaseStep';
import AcceptanceStep from './onboarding/steps/AcceptanceStep';
import AdvancedConfigStep from './onboarding/steps/AdvancedConfigStep';

import { TrustProvider, useTrust } from './trust';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';
const ONBOARDING_API_BASE = `${API_BASE_URL}/api/onboarding`;

const STEPS_APPLICANT = ['Choose Your Role', 'Join Organization', 'Connect Wallet', 'Complete'];
const STEPS_VENDOR = ['Choose Your Role', 'Create Organization', 'Trust Profile', 'Business Context', 'Technical Identity', 'Review', 'Complete'];
const STEPS_VENDOR_SKIP_TRUST = ['Choose Your Role', 'Create Organization', 'Trust Profile', 'Complete'];

/**
 * Dot-based Progress Indicator Component
 */
const DotProgress = ({ steps, activeStep }) => (
  <Box
    sx={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      gap: 1.5,
      py: 2,
    }}
    data-testid="dot-progress"
  >
    {steps.map((_, index) => (
      <Box
        key={index}
        sx={{
          width: 10,
          height: 10,
          borderRadius: '50%',
          bgcolor: index <= activeStep ? 'primary.main' : 'grey.300',
          transition: 'background-color 0.3s ease',
        }}
        data-testid={`dot-${index}`}
      />
    ))}
  </Box>
);

/**
 * Main Onboarding Page Component
 */
const OnboardingPage = () => {
  const branding = useBranding();
  const navigate = useNavigate();
  const { user, refreshUser } = useAuth();

  // State
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  // User selections
  const [userType, setUserType] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [existingOrganization, setExistingOrganization] = useState(null);
  const [roleLocked, setRoleLocked] = useState(false);
  
  // Applicant join options
  const [joinMethod, setJoinMethod] = useState('code'); // 'code', 'browse', 'skip'
  const [inviteCode, setInviteCode] = useState('');
  
  // Vendor org creation
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgDescription, setNewOrgDescription] = useState('');
  const [newOrgType, setNewOrgType] = useState('');
  const [jurisdiction, setJurisdiction] = useState('');
  const [isDiscoverable, setIsDiscoverable] = useState(false);
  const [membershipMode, setMembershipMode] = useState('invite_only');
  const [orgNameChecking, setOrgNameChecking] = useState(false);
  const [orgNameAvailable, setOrgNameAvailable] = useState(null);
  const [orgNameError, setOrgNameError] = useState(null);
  
  // Result state
  const [resultInviteCode, setResultInviteCode] = useState(null);
  const [resultOrgName, setResultOrgName] = useState(null);
  const [membershipStatus, setMembershipStatus] = useState(null);
  
  // Wallet pairing state
  const [walletPaired, setWalletPaired] = useState(false);
  const [pairedDeviceId, setPairedDeviceId] = useState(null);

  // Business-focused onboarding state
  const [selectedUseCases, setSelectedUseCases] = useState([]);
  const [selectedAcceptance, setSelectedAcceptance] = useState([]);
  const [manualProfiles, setManualProfiles] = useState([]);

  // Trust configuration state
  const [trustProfile, setTrustProfile] = useState([]);
  const [verifierConfig, setVerifierConfig] = useState({
    certificate: null,
    keyLocation: null,
    keyLocationConfig: {},
  });
  const [issuerConfig, setIssuerConfig] = useState({
    accessCertificate: null,
    signingCertificate: null,
    keyLocation: null,
    keyLocationConfig: {},
  });
  const [trustSettings, setTrustSettings] = useState({
    useEuTrustList: true,
    countries: [],
    documentTypes: [],
    documentTypes: [],
    revocationPolicy: 'soft_fail',
  });
  const [trustHealthValidated, setTrustHealthValidated] = useState(false);
  const [skipTrustSetup, setSkipTrustSetup] = useState(false);

  // Confirmation dialog
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [selectedOrgForConfirm, setSelectedOrgForConfirm] = useState(null);

  // Check onboarding status on mount
  useEffect(() => {
    checkOnboardingStatus();
  }, []);

  useEffect(() => {
    if (roleLocked && userType && activeStep === 0) {
      setActiveStep(1);
    }
  }, [roleLocked, userType, activeStep]);

  const checkOnboardingStatus = async () => {
    try {
      const response = await fetch(`${ONBOARDING_API_BASE}/status`, {
        credentials: 'include',
      });

      if (response.status === 401) {
        navigate('/');
        return;
      }

      const data = await response.json();

      if (!data.needs_onboarding) {
        if (data.user_type === 'vendor') {
          navigate('/vendor');
        } else if (data.user_type === 'administrator') {
          navigate('/admin');
        } else {
          navigate('/credentials');
        }
        return;
      }

      const resolvedUserType = data.user_type || user?.user_type || null;
      if (resolvedUserType) {
        setUserType(resolvedUserType);
      }

      if (resolvedUserType === 'vendor') {
        setRoleLocked(true);
        if (data.organization_id) {
          const existing = {
            id: data.organization_id,
            name: data.organization_name || '',
          };
          setExistingOrganization(existing);
          if (existing.name) {
            setNewOrgName(existing.name);
          }
          await loadOrgSettings();
        }
      } else {
        await loadOrganizations();
      }
      setLoading(false);
    } catch (err) {
      console.error('Error checking onboarding status:', err);
      setError('Failed to load onboarding status');
      setLoading(false);
    }
  };

  const loadOrganizations = async () => {
    try {
      const response = await fetch(`${ONBOARDING_API_BASE}/organizations`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setOrganizations(data.organizations || []);
      }
    } catch (err) {
      console.error('Error loading organizations:', err);
    }
  };

  const loadOrgSettings = async () => {
    try {
      const response = await fetch(`${ONBOARDING_API_BASE}/org-settings`, {
        credentials: 'include',
      });

      if (!response.ok) {
        return;
      }

      const data = await response.json();
      if (typeof data.is_discoverable === 'boolean') {
        setIsDiscoverable(data.is_discoverable);
      }
      if (data.membership_mode) {
        setMembershipMode(data.membership_mode);
      }
      if (data.organization_name && !newOrgName) {
        setNewOrgName(data.organization_name);
      }
    } catch (err) {
      console.error('Error loading organization settings:', err);
    }
  };

  const handleNext = () => {
    if (activeStep === 0 && !userType) {
      setError('Please select a role to continue');
      return;
    }
    setError(null);
    setActiveStep((prev) => prev + 1);
  };

  const handleBack = () => {
    setError(null);
    setActiveStep((prev) => prev - 1);
  };

  const handleRoleSelect = (role) => {
    if (roleLocked) {
      return;
    }
    setUserType(role);
  };

  const handleJoinWithCode = async () => {
    if (!inviteCode.trim()) {
      setError('Please enter an invite code');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const response = await fetch(`${ONBOARDING_API_BASE}/join-with-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ invite_code: inviteCode.trim() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Invalid invite code');
      }

      setResultOrgName(data.organization_name);
      setMembershipStatus('joined');
      // Move to wallet pairing step
      setActiveStep(2);
      setSubmitting(false);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  const handleSelectOrg = (org) => {
    if (org.membership_mode === 'invite_only') {
      setError('This organization only accepts members via invitation. Please use an invite code.');
      return;
    }
    setSelectedOrgForConfirm(org);
    setConfirmDialogOpen(true);
  };

  const handleConfirmOrgSelection = async () => {
    setConfirmDialogOpen(false);
    setSubmitting(true);
    setError(null);

    const org = selectedOrgForConfirm;

    try {
      const response = await fetch(`${ONBOARDING_API_BASE}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          user_type: 'applicant',
          organization_id: org.id,
          confirm_organization: true,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to join organization');
      }

      setResultOrgName(data.organization_name);
      setMembershipStatus(data.membership_status);
      // Move to wallet pairing step
      setActiveStep(2);
      setSubmitting(false);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  const handleCompleteApplicantWithoutOrg = async () => {
    // Skip org, go directly to wallet pairing
    setMembershipStatus('none');
    setActiveStep(2);
  };

  const handleFinalizeApplicantOnboarding = async (withWallet = false) => {
    setSubmitting(true);
    setError(null);

    try {
      const response = await fetch(`${ONBOARDING_API_BASE}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          user_type: 'applicant',
          organization_id: selectedOrgForConfirm?.id || null,
          wallet_paired: withWallet,
          device_id: pairedDeviceId,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to complete setup');
      }

      // Move to completion step
      setActiveStep(3);
      setSubmitting(false);

      // Refresh user to update onboarding status
      await refreshUser();

      // Redirect after showing completion
      setTimeout(() => {
        navigate('/credentials');
      }, 3000);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  const checkOrgNameAvailability = useCallback(async (name) => {
    if (!name || name.trim().length < 3) {
      setOrgNameAvailable(null);
      setOrgNameError(null);
      return;
    }

    setOrgNameChecking(true);
    setOrgNameError(null);

    try {
      const response = await fetch(
        `${ONBOARDING_API_BASE}/check-organization-name?name=${encodeURIComponent(name.trim())}`,
        { credentials: 'include' }
      );

      const data = await response.json();

      if (!response.ok) {
        setOrgNameError(data.detail || 'Failed to check name availability');
        setOrgNameAvailable(false);
      } else {
        setOrgNameAvailable(data.available);
        if (!data.available) {
          setOrgNameError(`Organization name "${name}" is already taken. Please choose a different name.`);
        }
      }
    } catch (err) {
      console.error('Error checking org name:', err);
      setOrgNameError('Failed to check name availability');
      setOrgNameAvailable(null);
    } finally {
      setOrgNameChecking(false);
    }
  }, []);

  // Debounce organization name checking
  useEffect(() => {
    const isExistingOrg = Boolean(existingOrganization?.id);
    if (isExistingOrg || userType !== 'vendor') {
      return;
    }

    const timer = setTimeout(() => {
      if (newOrgName && newOrgName.trim().length >= 3) {
        checkOrgNameAvailability(newOrgName);
      }
    }, 500); // 500ms debounce

    return () => clearTimeout(timer);
  }, [newOrgName, existingOrganization, userType, checkOrgNameAvailability]);

  const handleCreateOrgNext = () => {
    const isExistingOrg = Boolean(existingOrganization?.id);

    if (!isExistingOrg && !newOrgName.trim()) {
      setError('Please enter an organization name');
      return;
    }

    if (!isExistingOrg && newOrgName.trim().length < 3) {
      setError('Organization name must be at least 3 characters');
      return;
    }

    // Check if name validation is still in progress
    if (orgNameChecking) {
      setError('Checking organization name availability...');
      return;
    }

    // Check if name is available
    if (orgNameAvailable === false) {
      setError(orgNameError || 'Organization name is already taken');
      return;
    }

    // Name validation passed, move to trust profile step
    setError(null);
    setActiveStep(2); // Move to trust profile selection
  };

  const handleCompleteVendor = async () => {
    const isExistingOrg = Boolean(existingOrganization?.id);

    if (!isExistingOrg && !newOrgName.trim()) {
      setError('Please enter an organization name');
      return;
    }

    if (!trustProfile || trustProfile.length === 0) {
      setError('Please select at least one trust profile');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const payload = {
        user_type: 'vendor',
        is_discoverable: isDiscoverable,
        membership_mode: membershipMode,
        trust_framework_codes: trustProfile, // Send array of codes
      };

      if (isExistingOrg) {
        payload.organization_id = existingOrganization.id;
      } else {
        payload.organization_name = newOrgName.trim();
        payload.organization_description = newOrgDescription.trim() || null;
        payload.organization_type = newOrgType || null;
        payload.jurisdiction = jurisdiction.trim() || null;
      }

      const response = await fetch(`${ONBOARDING_API_BASE}/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        const fallbackMessage = isExistingOrg
          ? 'Failed to save organization settings'
          : 'Failed to create organization';
        throw new Error(data.detail || fallbackMessage);
      }

      setResultOrgName(data.organization_name);
      setResultInviteCode(data.invite_code);
      setMembershipStatus('owner');
      
      // Move to business context step (step 3)
      setActiveStep(3);
      setSubmitting(false);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  // Business-focused step handlers
  const handleBusinessContextNext = () => {
    if (selectedUseCases.length === 0) {
      setError('Please select at least one credential type');
      return;
    }
    if (selectedAcceptance.length === 0) {
      setError('Please select at least one acceptance type');
      return;
    }
    if (!jurisdiction) {
      setError('Please select your jurisdiction');
      return;
    }
    setError(null);
    setActiveStep(4); // Move to Technical Identity
  };

  const handleUseCasesNext = () => {
    if (selectedUseCases.length === 0) {
      setError('Please select at least one credential type');
      return;
    }
    setError(null);
    setActiveStep(4); // Legacy - now handled by BusinessContextNext
  };

  const handleAcceptanceNext = () => {
    if (selectedAcceptance.length === 0) {
      setError('Please select at least one acceptance type');
      return;
    }
    if (!jurisdiction) {
      setError('Please select your jurisdiction');
      return;
    }
    setError(null);
    setActiveStep(5); // Move to Trust Profile (legacy compatibility)
  };

  const handleTechnicalIdentityNext = () => {
    setError(null);
    setActiveStep(5); // Move to Health Check
  };

  // Trust step handlers (legacy compatibility)
  const handleTrustProfileSelect = (profile) => {
    // Toggle selection for multi-select
    setTrustProfile(prev => {
      if (prev.includes(profile)) {
        return prev.filter(p => p !== profile);
      } else {
        return [...prev, profile];
      }
    });
  };

  const handleTrustProfileNext = () => {
    if (!trustProfile || trustProfile.length === 0) {
      setError('Please select at least one trust profile to continue');
      return;
    }
    setError(null);
    // After selecting trust profile(s), create the organization
    handleCompleteVendor();
  };

  const handleVerifierConfigChange = useCallback((config) => {
    setVerifierConfig(config);
  }, []);

  const handleVerifierNext = () => {
    setError(null);
    setActiveStep(7); // Move to Issuer Identity (adjusted for new flow)
  };

  const handleIssuerConfigChange = useCallback((config) => {
    setIssuerConfig(config);
  }, []);

  const handleIssuerNext = () => {
    setError(null);
    setActiveStep(8); // Move to Trust Sources (adjusted for new flow)
  };

  const handleTrustSettingsChange = useCallback((settings) => {
    setTrustSettings(prev => ({ ...prev, ...settings }));
  }, []);

  const handleTrustSourcesNext = () => {
    setError(null);
    setActiveStep(4); // Move to Health Check (new consolidated flow)
  };

  const handleTrustHealthComplete = async (activate = true) => {
    setSubmitting(true);
    setError(null);

    try {
      // TODO: Save trust configuration to backend when endpoint is ready
      // For now, skip the API call and just complete onboarding
      /*
      const trustConfig = {
        trust_profile: trustProfile,
        verifier_config: verifierConfig,
        issuer_config: issuerConfig,
        trust_settings: trustSettings,
        activated: activate,
        // Include business context for profile generation
        use_cases: selectedUseCases,
        acceptance_types: selectedAcceptance,
        jurisdiction: jurisdiction,
        manual_profiles: manualProfiles,
      };

      const response = await fetch(`${API_BASE_URL}/api/trust/config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(trustConfig),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to save trust configuration');
      }
      */

      setTrustHealthValidated(true);
      setActiveStep(5); // Move to Completion (new consolidated flow)
      setSubmitting(false);

      // Refresh user and redirect
      await refreshUser();
      setTimeout(() => {
        navigate('/vendor');
      }, 5000);
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  const handleSkipTrustSetup = async () => {
    setSkipTrustSetup(true);
    setActiveStep(6); // Jump directly to completion (new consolidated flow with trust profile step)
    
    // Still refresh user and redirect
    await refreshUser();
    setTimeout(() => {
      navigate('/vendor');
    }, 5000);
  };

  // Loading state
  if (loading) {
    return (
      <Box
        sx={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'linear-gradient(135deg, #1976d2 0%, #42a5f5 100%)',
        }}
        data-testid="onboarding-loading"
      >
        <CircularProgress size={48} sx={{ color: 'white' }} />
      </Box>
    );
  }

  const vendorSteps = existingOrganization
    ? ['Choose Your Role', 'Organization Settings', 'Business Context', 'Technical Identity', 'Review', 'Complete']
    : (skipTrustSetup ? STEPS_VENDOR_SKIP_TRUST : STEPS_VENDOR);
  const steps = userType === 'vendor' ? vendorSteps : STEPS_APPLICANT;

  return (
    <TrustProvider>
      <Box
        sx={{
          minHeight: '100vh',
          background: 'linear-gradient(135deg, #1976d2 0%, #42a5f5 100%)',
          py: 4,
        }}
        data-testid="onboarding-page"
      >
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ textAlign: 'center', mb: 4 }} data-testid="onboarding-header">
          <FlightTakeoffIcon sx={{ fontSize: 48, color: 'white', mb: 1 }} />
          <Typography variant="h4" fontWeight="bold" color="white" data-testid="onboarding-title">
            Welcome
          </Typography>
          <Typography variant="subtitle1" color="rgba(255,255,255,0.9)">
            Let's get you set up
          </Typography>
        </Box>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)} data-testid="onboarding-error">
            {error}
          </Alert>
        )}

        {/* Step Content */}
        <Paper sx={{ p: 4, minHeight: 400 }} data-testid="onboarding-content">
          {/* Step 1: Role Selection */}
          <Fade in={activeStep === 0} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 0 && (
                <RoleSelectionStep
                  userType={userType}
                  onSelectRole={handleRoleSelect}
                />
              )}
            </Box>
          </Fade>

          {/* Step 2: Applicant - Join Organization */}
          <Fade in={activeStep === 1 && userType === 'applicant'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 1 && userType === 'applicant' && (
                <ApplicantJoinStep
                  joinMethod={joinMethod}
                  onJoinMethodChange={setJoinMethod}
                  inviteCode={inviteCode}
                  onInviteCodeChange={setInviteCode}
                  organizations={organizations}
                  submitting={submitting}
                  onJoinWithCode={handleJoinWithCode}
                  onSelectOrg={handleSelectOrg}
                  onSkip={handleCompleteApplicantWithoutOrg}
                />
              )}
            </Box>
          </Fade>

          {/* Step 2: Vendor - Create Organization */}
          <Fade in={activeStep === 1 && userType === 'vendor'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 1 && userType === 'vendor' && (
                <VendorCreateOrgStep
                  orgName={newOrgName}
                  onOrgNameChange={setNewOrgName}
                  orgDescription={newOrgDescription}
                  onOrgDescriptionChange={setNewOrgDescription}
                  orgType={newOrgType}
                  onOrgTypeChange={setNewOrgType}
                  jurisdiction={jurisdiction}
                  onJurisdictionChange={setJurisdiction}
                  isDiscoverable={isDiscoverable}
                  onDiscoverableChange={setIsDiscoverable}
                  membershipMode={membershipMode}
                  onMembershipModeChange={setMembershipMode}
                  orgDetailsLocked={Boolean(existingOrganization)}
                  orgNameChecking={orgNameChecking}
                  orgNameAvailable={orgNameAvailable}
                  orgNameError={orgNameError}
                />
              )}
            </Box>
          </Fade>

          {/* Step 3: Vendor - Trust Profile Selection */}
          <Fade in={activeStep === 2 && userType === 'vendor'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 2 && userType === 'vendor' && (
                <TrustProfileStep
                  selectedProfile={trustProfile}
                  onProfileChange={handleTrustProfileSelect}
                  disabled={submitting}
                />
              )}
            </Box>
          </Fade>

          {/* Step 4: Vendor - Business Context (consolidates Use Cases + Acceptance + Jurisdiction) */}
          <Fade in={activeStep === 3 && userType === 'vendor'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 3 && userType === 'vendor' && (
                <BusinessContextStep
                  selectedUseCases={selectedUseCases}
                  onUseCasesChange={setSelectedUseCases}
                  selectedAcceptance={selectedAcceptance}
                  onAcceptanceChange={setSelectedAcceptance}
                  jurisdiction={jurisdiction}
                  onJurisdictionChange={setJurisdiction}
                />
              )}
            </Box>
          </Fade>

          {/* Step 5: Vendor - Technical Identity (consolidates Verifier + Issuer + Trust Sources) */}
          <Fade in={activeStep === 4 && userType === 'vendor'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 4 && userType === 'vendor' && (
                <TechnicalIdentityStep
                  verifierConfig={verifierConfig}
                  onVerifierConfigChange={handleVerifierConfigChange}
                  issuerConfig={issuerConfig}
                  onIssuerConfigChange={handleIssuerConfigChange}
                  trustSettings={trustSettings}
                  onTrustSettingsChange={handleTrustSettingsChange}
                  trustProfile={trustProfile}
                />
              )}
            </Box>
          </Fade>

          {/* Step 6: Vendor - Trust Health Check (Review) */}
          <Fade in={activeStep === 5 && userType === 'vendor'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 5 && userType === 'vendor' && (
                <TrustHealthCheckStep
                  trustProfile={trustProfile}
                  verifierConfig={verifierConfig}
                  issuerConfig={issuerConfig}
                  trustSettings={trustSettings}
                  onActivate={() => handleTrustHealthComplete(true)}
                  onReviewLater={() => handleTrustHealthComplete(false)}
                  submitting={submitting}
                />
              )}
            </Box>
          </Fade>

          {/* Step 3: Applicant - Wallet Pairing */}
          <Fade in={activeStep === 2 && userType === 'applicant'} timeout={300} unmountOnExit>
            <Box>
              {activeStep === 2 && userType === 'applicant' && (
                <WalletPairingStep
                  onPairingComplete={(data) => {
                    setWalletPaired(true);
                    setPairedDeviceId(data.device_id);
                    handleFinalizeApplicantOnboarding(true);
                  }}
                  onSkip={() => handleFinalizeApplicantOnboarding(false)}
                  submitting={submitting}
                />
              )}
            </Box>
          </Fade>

          {/* Step 3/6: Completion */}
          <Fade in={(activeStep === 3 && userType === 'applicant') || (activeStep === 6 && userType === 'vendor') || (activeStep === 3 && userType === 'vendor' && skipTrustSetup)} timeout={300} unmountOnExit>
            <Box>
              {((activeStep === 3 && userType === 'applicant') || 
                (activeStep === 6 && userType === 'vendor') ||
                (activeStep === 3 && userType === 'vendor' && skipTrustSetup)) && (
                <CompletionStep
                  userType={userType}
                  resultOrgName={resultOrgName}
                  resultInviteCode={resultInviteCode}
                  membershipStatus={membershipStatus}
                  walletPaired={walletPaired}
                  pairedDeviceId={pairedDeviceId}
                  existingOrganization={Boolean(existingOrganization)}
                  trustConfigured={trustHealthValidated && !skipTrustSetup}
                  trustSkipped={skipTrustSetup}
                />
              )}
            </Box>
          </Fade>

          {/* Navigation Buttons */}
          {activeStep < (userType === 'vendor' ? 5 : 2) && (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                mt: 4,
                pt: 3,
                borderTop: '1px solid',
                borderColor: 'divider',
              }}
              data-testid="onboarding-nav-buttons"
            >
              <Button
                disabled={activeStep === 0 || (roleLocked && activeStep === 1)}
                onClick={handleBack}
                startIcon={<ArrowBackIcon />}
                data-testid="onboarding-back-btn"
              >
                Back
              </Button>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                {/* Skip trust setup link - show on trust profile step */}
                {activeStep === 2 && userType === 'vendor' && (
                  <Link
                    component="button"
                    variant="body2"
                    onClick={handleSkipTrustSetup}
                    sx={{ color: 'text.secondary' }}
                    data-testid="skip-trust-setup-link"
                  >
                    <ScheduleIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'text-bottom' }} />
                    Set up later
                  </Link>
                )}

                {/* Next button logic */}
                {activeStep === 1 && userType === 'vendor' && (
                  <Button
                    variant="contained"
                    onClick={handleCreateOrgNext}
                    disabled={submitting || (existingOrganization ? false : !newOrgName.trim())}
                    endIcon={submitting ? <CircularProgress size={20} /> : <ArrowForwardIcon />}
                    data-testid="onboarding-next-btn"
                  >
                    Next
                  </Button>
                )}

                {activeStep === 2 && userType === 'vendor' && (
                  <Button
                    variant="contained"
                    onClick={handleTrustProfileNext}
                    disabled={submitting || !trustProfile || trustProfile.length === 0}
                    endIcon={submitting ? <CircularProgress size={20} /> : <ArrowForwardIcon />}
                    data-testid="onboarding-next-btn"
                  >
                    {submitting ? 'Creating Organization...' : 'Continue'}
                  </Button>
                )}

                {activeStep === 3 && userType === 'vendor' && (
                  <Button
                    variant="contained"
                    onClick={handleBusinessContextNext}
                    disabled={submitting || selectedUseCases.length === 0 || selectedAcceptance.length === 0 || !jurisdiction}
                    endIcon={<ArrowForwardIcon />}
                    data-testid="onboarding-next-btn"
                  >
                    Next
                  </Button>
                )}

                {activeStep === 4 && userType === 'vendor' && (
                  <Button
                    variant="contained"
                    onClick={handleTechnicalIdentityNext}
                    disabled={submitting}
                    endIcon={<ArrowForwardIcon />}
                    data-testid="onboarding-next-btn"
                  >
                    Next
                  </Button>
                )}

                {activeStep === 0 && (
                  <Button
                    variant="contained"
                    onClick={handleNext}
                    disabled={!userType}
                    endIcon={<ArrowForwardIcon />}
                    data-testid="onboarding-next-btn"
                  >
                    Next
                  </Button>
                )}
              </Box>
            </Box>
          )}
        </Paper>

        {/* Dot Progress Indicator - at bottom */}
        <DotProgress steps={steps} activeStep={activeStep} />
      </Container>

      {/* Confirmation Dialog */}
      <ConfirmOrgDialog
        open={confirmDialogOpen}
        onClose={() => setConfirmDialogOpen(false)}
        organization={selectedOrgForConfirm}
        submitting={submitting}
        onConfirm={handleConfirmOrgSelection}
      />
    </Box>
    </TrustProvider>
  );
};

export default OnboardingPage;
