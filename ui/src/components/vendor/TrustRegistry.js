/**
 * Trust Registry Page
 * 
 * Vendor-facing page for managing trust frameworks, certificate chains,
 * trust anchors, and key management.
 * 
 * Consolidates:
 * - Trust profile selection (EUDI, ICAO, AAMVA, Custom)
 * - Certificate chain status and validation
 * - Trust health dashboard
 * - Key management and rotation
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Alert,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  Chip,
  Divider,
  CircularProgress,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import PublicIcon from '@mui/icons-material/Public';
import FlightIcon from '@mui/icons-material/Flight';
import DirectionsCarIcon from '@mui/icons-material/DirectionsCar';
import SettingsIcon from '@mui/icons-material/Settings';
import SchoolIcon from '@mui/icons-material/School';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

import { useTrust, TrustProvider, TrustChainStatus, TrustHealthChecklist } from '../trust';
import { useAuth } from '../../hooks/useAuth';
import RevocationManager from './RevocationManager';

/**
 * Trust framework display configuration
 */
const TRUST_FRAMEWORKS = [
  {
    id: 'eudi',
    name: 'EU Digital Identity Wallet (EUDI)',
    description: 'Use EU trusted lists and wallet-compatible certificates. Recommended for Europe.',
    icon: <PublicIcon sx={{ fontSize: 40 }} />,
    color: '#0033A0', // EU blue
  },
  {
    id: 'icao',
    name: 'ICAO PKD',
    description: 'Use ICAO Public Key Directory for passport verification. Recommended for travel.',
    icon: <FlightIcon sx={{ fontSize: 40 }} />,
    color: '#003087', // ICAO blue
  },
  {
    id: 'aamva',
    name: 'AAMVA',
    description: 'Use AAMVA standards for driver licenses and state IDs. Recommended for North America.',
    icon: <DirectionsCarIcon sx={{ fontSize: 40 }} />,
    color: '#C8102E', // AAMVA red
  },
  {
    id: 'open_badges',
    name: 'Open Badges 3.0',
    description: 'Issue educational credentials, certifications, and skill badges. Supports X.509 certificates with W3C Verifiable Credentials.',
    icon: <SchoolIcon sx={{ fontSize: 40 }} />,
    color: '#FF6B35', // Open Badges brand color
  },
  {
    id: 'custom',
    name: 'Custom X.509',
    description: 'Manage your own certificate trust anchors for private PKI.',
    icon: <SettingsIcon sx={{ fontSize: 40 }} />,
    color: '#757575', // Gray
  },
];

/**
 * Tab Panel Component
 */
function TabPanel({ children, value, index, ...other }) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`trust-tabpanel-${index}`}
      aria-labelledby={`trust-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

/**
 * Trust Framework Card Component
 */
function TrustFrameworkCard({ framework, active, onSelect, trustProfile, onViewDetails, onFixIssues }) {
  const isConfigured = active && trustProfile?.verifierCertificate;
  const hasIssues = active && (!trustProfile?.verifierCertificate || !trustProfile?.issuerKeys?.length);

  return (
    <Card
      sx={{
        border: 1,
        borderColor: active ? 'primary.main' : 'divider',
        bgcolor: active ? 'action.selected' : 'background.paper',
      }}
    >
      <CardContent>
        <Grid container spacing={2} alignItems="center">
          {/* Icon and Name */}
          <Grid item xs={12} md={4}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Box sx={{ color: framework.color }}>
                {framework.icon}
              </Box>
              <Box>
                <Typography variant="h6">
                  {framework.name}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {framework.description}
                </Typography>
              </Box>
            </Box>
          </Grid>

          {/* Status */}
          <Grid item xs={12} md={4}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {!active ? (
                <Chip
                  label="Not Configured"
                  color="default"
                  size="small"
                  sx={{ width: 'fit-content' }}
                />
              ) : hasIssues ? (
                <>
                  <Chip
                    label="Active - Needs Attention"
                    color="warning"
                    size="small"
                    icon={<SecurityIcon />}
                    sx={{ width: 'fit-content' }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {!trustProfile?.verifierCertificate && 'Missing verifier certificate. '}
                    {!trustProfile?.issuerKeys?.length && 'Missing issuer keys.'}
                  </Typography>
                </>
              ) : isConfigured ? (
                <>
                  <Chip
                    label="Active - Configured"
                    color="success"
                    size="small"
                    icon={<CheckCircleIcon />}
                    sx={{ width: 'fit-content' }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {trustProfile?.verifierCertificate && 'Certificate configured. '}
                    {trustProfile?.issuerKeys?.length > 0 && `${trustProfile.issuerKeys.length} key(s) configured.`}
                  </Typography>
                </>
              ) : (
                <Chip
                  label="Active - Pending Setup"
                  color="info"
                  size="small"
                  sx={{ width: 'fit-content' }}
                />
              )}
            </Box>
          </Grid>

          {/* Actions */}
          <Grid item xs={12} md={4}>
            <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
              {active ? (
                <>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={onViewDetails}
                  >
                    View Details
                  </Button>
                  {hasIssues && (
                    <Button
                      variant="contained"
                      size="small"
                      color="warning"
                      onClick={onFixIssues}
                    >
                      Fix Issues
                    </Button>
                  )}
                </>
              ) : (
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => onSelect(framework.id)}
                >
                  Configure
                </Button>
              )}
            </Box>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
}

/**
 * Trust Registry Main Component (Inner - uses TrustProvider context)
 */
function TrustRegistryContent() {
  const { organizationId } = useAuth();
  const {
    trustProfile,
    healthStatus,
    loading,
    error,
    loadTrustProfile,
    refreshHealth,
  } = useTrust();

  const [currentTab, setCurrentTab] = useState(0);
  const [selectedFramework, setSelectedFramework] = useState('eudi');
  const loadedRef = React.useRef(false);

  // Load trust profile on mount (only once)
  useEffect(() => {
    if (organizationId && !loadedRef.current) {
      loadedRef.current = true;
      loadTrustProfile(organizationId);
    }
  }, [organizationId, loadTrustProfile]);

  // Set selected framework from profile
  useEffect(() => {
    if (trustProfile?.trustFramework) {
      setSelectedFramework(trustProfile.trustFramework.toLowerCase());
    }
  }, [trustProfile]);

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

  const handleFrameworkSelect = (frameworkId) => {
    setSelectedFramework(frameworkId);
    // TODO: Call API to update trust framework
    console.log('Selected framework:', frameworkId);
  };

  const handleRefreshHealth = async () => {
    if (organizationId) {
      await refreshHealth();
    }
  };

  if (loading && !trustProfile) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box data-testid="trust-registry-page">
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SecurityIcon fontSize="large" />
          Trust
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor trust framework status, manage certificate chains, and configure key infrastructure for secure credential operations.
        </Typography>
      </Box>

      {/* Error Alert - only show non-auth errors */}
      {error && !error.toLowerCase().includes('auth') && !error.includes('401') && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => {}}>
          {error}
        </Alert>
      )}

      {/* Not Configured Alert */}
      {!loading && (!trustProfile || trustProfile.trustFramework === 'CUSTOM') && (
        <Alert severity="info" sx={{ mb: 3 }} icon={<SecurityIcon />}>
          <Typography variant="body2">
            <strong>Trust profile not fully configured.</strong> Select a trust framework below to get started.
          </Typography>
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          aria-label="trust registry tabs"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Overview" id="trust-tab-0" aria-controls="trust-tabpanel-0" />
          <Tab label="Frameworks" id="trust-tab-1" aria-controls="trust-tabpanel-1" />
          <Tab label="Certificate Chain" id="trust-tab-2" aria-controls="trust-tabpanel-2" />
          <Tab label="Keys" id="trust-tab-3" aria-controls="trust-tabpanel-3" />
          <Tab label="Revocations" id="trust-tab-4" aria-controls="trust-tabpanel-4" />
        </Tabs>

        {/* Tab 0: Overview */}
        <TabPanel value={currentTab} index={0}>
          <Grid container spacing={3}>
            {/* Current Framework */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: 'grey.50' }}>
                <Typography variant="h6" gutterBottom>
                  Active Framework
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                  {TRUST_FRAMEWORKS.find(f => f.id === selectedFramework)?.icon}
                  <Box>
                    <Typography variant="body1" fontWeight="bold">
                      {TRUST_FRAMEWORKS.find(f => f.id === selectedFramework)?.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {TRUST_FRAMEWORKS.find(f => f.id === selectedFramework)?.description}
                    </Typography>
                  </Box>
                </Box>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => setCurrentTab(1)}
                >
                  Change Framework
                </Button>
              </Paper>
            </Grid>

            {/* Quick Stats */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: 'grey.50' }}>
                <Typography variant="h6" gutterBottom>
                  Trust Status
                </Typography>
                {!trustProfile || !healthStatus ? (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    Trust profile not configured yet. Complete onboarding to set up trust framework.
                  </Alert>
                ) : (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2">Chain Status:</Typography>
                      <Chip
                        label={healthStatus?.chainStatus?.healthy ? 'Healthy' : 'Pending'}
                        size="small"
                        color={healthStatus?.chainStatus?.healthy ? 'success' : 'default'}
                      />
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2">All Checks:</Typography>
                      <Chip
                        label={healthStatus?.allPassed ? 'Passed' : 'Pending Setup'}
                        size="small"
                        color={healthStatus?.allPassed ? 'success' : 'default'}
                      />
                    </Box>
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={<RefreshIcon />}
                      onClick={handleRefreshHealth}
                      disabled={loading}
                      sx={{ mt: 1 }}
                    >
                      Refresh Status
                    </Button>
                  </Box>
                )}
              </Paper>
            </Grid>

            {/* Health Checklist */}
            <Grid item xs={12}>
              <Typography variant="h6" gutterBottom>
                Health Checks
              </Typography>
              <TrustHealthChecklist
                healthStatus={healthStatus}
                loading={loading}
                showChainStatus={false}
                showActions={false}
                compact
              />
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 1: Frameworks */}
        <TabPanel value={currentTab} index={1}>
          <Typography variant="h6" gutterBottom>
            Trust Framework Status
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Monitor the configuration status of each trust framework. Configure or fix issues as needed.
          </Typography>

          <Grid container spacing={3}>
            {TRUST_FRAMEWORKS.map((framework) => (
              <Grid item xs={12} key={framework.id}>
                <TrustFrameworkCard
                  framework={framework}
                  active={selectedFramework === framework.id}
                  onSelect={handleFrameworkSelect}
                  trustProfile={trustProfile}
                  onViewDetails={() => setCurrentTab(2)}
                  onFixIssues={() => setCurrentTab(3)}
                />
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Tab 2: Certificate Chain */}
        <TabPanel value={currentTab} index={2}>
          <Typography variant="h6" gutterBottom>
            Certificate Chain Status
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            View the status of your PKI trust chain including root CA, intermediate CA, and CRL.
          </Typography>

          <TrustChainStatus
            chainStatus={healthStatus?.chainStatus}
            loading={loading}
            showTitle={false}
            compact={false}
            onRefresh={handleRefreshHealth}
          />

          {healthStatus?.warnings && healthStatus.warnings.length > 0 && (
            <Alert severity="warning" sx={{ mt: 3 }}>
              <Typography variant="body2" fontWeight="bold" gutterBottom>
                Warnings:
              </Typography>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                {healthStatus.warnings.map((warning, index) => (
                  <li key={index}>{warning}</li>
                ))}
              </ul>
            </Alert>
          )}

          {healthStatus?.errors && healthStatus.errors.length > 0 && (
            <Alert severity="error" sx={{ mt: 3 }}>
              <Typography variant="body2" fontWeight="bold" gutterBottom>
                Errors:
              </Typography>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                {healthStatus.errors.map((error, index) => (
                  <li key={index}>{error}</li>
                ))}
              </ul>
            </Alert>
          )}
        </TabPanel>

        {/* Tab 3: Keys */}
        <TabPanel value={currentTab} index={3}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <VpnKeyIcon />
            Key Management
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Manage cryptographic keys for signing and verification.
          </Typography>

          <Alert severity="info">
            <Typography variant="body2">
              Key management interface coming soon. Keys are currently configured during onboarding.
            </Typography>
          </Alert>

          {trustProfile?.verifierKeys && trustProfile.verifierKeys.length > 0 && (
            <Paper sx={{ p: 3, mt: 3 }}>
              <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                Verifier Keys
              </Typography>
              {trustProfile.verifierKeys.map((key, index) => (
                <Box key={index} sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>Location:</strong> {key.location || 'Not specified'}
                  </Typography>
                  <Typography variant="body2">
                    <strong>Certificate:</strong> {key.hasCertificate ? 'Attached' : 'Not attached'}
                  </Typography>
                  <Divider sx={{ mt: 1 }} />
                </Box>
              ))}
            </Paper>
          )}

          {trustProfile?.issuerKeys && trustProfile.issuerKeys.length > 0 && (
            <Paper sx={{ p: 3, mt: 3 }}>
              <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                Issuer Keys
              </Typography>
              {trustProfile.issuerKeys.map((key, index) => (
                <Box key={index} sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>Location:</strong> {key.location || 'Not specified'}
                  </Typography>
                  <Typography variant="body2">
                    <strong>Certificate:</strong> {key.hasCertificate ? 'Attached' : 'Not attached'}
                  </Typography>
                  <Divider sx={{ mt: 1 }} />
                </Box>
              ))}
            </Paper>
          )}
        </TabPanel>

        {/* Tab 4: Revocations */}
        <TabPanel value={currentTab} index={4}>
          <RevocationManager />
        </TabPanel>
      </Paper>
    </Box>
  );
}

/**
 * Trust Registry Wrapper Component (provides TrustProvider context)
 */
export default function TrustRegistry() {
  return (
    <TrustProvider>
      <TrustRegistryContent />
    </TrustProvider>
  );
}
