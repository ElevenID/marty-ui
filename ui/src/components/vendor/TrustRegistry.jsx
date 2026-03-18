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
import { useTranslation } from 'react-i18next';
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

import { TrustProvider, TrustChainStatus, TrustHealthChecklist } from '../trust';
import { useTrust } from '../trust/trustHooks';
import { useAuth } from '../../hooks/useAuth';
import RevocationManager from './RevocationManager';

/**
 * Trust framework display configuration
 * Note: Framework data is now created inside component to access translation function
 */
function getTrustFrameworks(t) {
  return [
    {
      id: 'eudi',
      name: t('trustRegistry.frameworks.eudi.name'),
      description: t('trustRegistry.frameworks.eudi.description'),
      icon: <PublicIcon sx={{ fontSize: 40 }} />,
      color: '#0033A0',
    },
    {
      id: 'icao',
      name: t('trustRegistry.frameworks.icao.name'),
      description: t('trustRegistry.frameworks.icao.description'),
      icon: <FlightIcon sx={{ fontSize: 40 }} />,
      color: '#003087',
    },
    {
      id: 'aamva',
      name: t('trustRegistry.frameworks.aamva.name'),
      description: t('trustRegistry.frameworks.aamva.description'),
      icon: <DirectionsCarIcon sx={{ fontSize: 40 }} />,
      color: '#C8102E',
    },
    {
      id: 'open_badges',
      name: t('trustRegistry.frameworks.openBadges.name'),
      description: t('trustRegistry.frameworks.openBadges.description'),
      icon: <SchoolIcon sx={{ fontSize: 40 }} />,
      color: '#FF6B35',
    },
    {
      id: 'custom',
      name: t('trustRegistry.frameworks.custom.name'),
      description: t('trustRegistry.frameworks.custom.description'),
      icon: <SettingsIcon sx={{ fontSize: 40 }} />,
      color: '#757575',
    },
  ];
}

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
function TrustFrameworkCard({ framework, active, onSelect, trustProfile, onViewDetails, onFixIssues, t }) {
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
                  label={t('trustRegistry.status.notConfigured')}
                  color="default"
                  size="small"
                  sx={{ width: 'fit-content' }}
                />
              ) : hasIssues ? (
                <>
                  <Chip
                    label={t('trustRegistry.status.needsAttention')}
                    color="warning"
                    size="small"
                    icon={<SecurityIcon />}
                    sx={{ width: 'fit-content' }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {!trustProfile?.verifierCertificate && `${t('trustRegistry.status.missingVerifierCert')} `}
                    {!trustProfile?.issuerKeys?.length && t('trustRegistry.status.missingIssuerKeys')}
                  </Typography>
                </>
              ) : isConfigured ? (
                <>
                  <Chip
                    label={t('trustRegistry.status.configured')}
                    color="success"
                    size="small"
                    icon={<CheckCircleIcon />}
                    sx={{ width: 'fit-content' }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {trustProfile?.verifierCertificate && `${t('trustRegistry.status.certConfigured')} `}
                    {trustProfile?.issuerKeys?.length > 0 && t('trustRegistry.status.keysConfigured', { count: trustProfile.issuerKeys.length })}
                  </Typography>
                </>
              ) : (
                <Chip
                  label={t('trustRegistry.status.pendingSetup')}
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
                    {t('trustRegistry.buttons.viewDetails')}
                  </Button>
                  {hasIssues && (
                    <Button
                      variant="contained"
                      size="small"
                      color="warning"
                      onClick={onFixIssues}
                    >
                      {t('trustRegistry.buttons.fixIssues')}
                    </Button>
                  )}
                </>
              ) : (
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => onSelect(framework.id)}
                >
                  {t('trustRegistry.buttons.configure')}
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
  const { t } = useTranslation('vendor');
  const TRUST_FRAMEWORKS = getTrustFrameworks(t);
  const { organizationId } = useAuth();
  const {
    trustProfile,
    healthStatus,
    loading,
    error,
    loadTrustProfile,
    refreshHealth,
    updateTrustProfile,
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

  const handleFrameworkSelect = async (frameworkId) => {
    setSelectedFramework(frameworkId);
    if (organizationId) {
      await updateTrustProfile({ trustFramework: frameworkId });
    }
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
          {t('trustRegistry.title')}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          {t('trustRegistry.description')}
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
            <strong>{t('trustRegistry.notConfigured')}</strong> {t('trustRegistry.selectFramework')}
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
          <Tab label={t('trustRegistry.tabs.overview')} id="trust-tab-0" aria-controls="trust-tabpanel-0" />
          <Tab label={t('trustRegistry.tabs.frameworks')} id="trust-tab-1" aria-controls="trust-tabpanel-1" />
          <Tab label={t('trustRegistry.tabs.certificates')} id="trust-tab-2" aria-controls="trust-tabpanel-2" />
          <Tab label={t('trustRegistry.tabs.keys')} id="trust-tab-3" aria-controls="trust-tabpanel-3" />
          <Tab label={t('trustRegistry.tabs.revocations')} id="trust-tab-4" aria-controls="trust-tabpanel-4" />
        </Tabs>

        {/* Tab 0: Overview */}
        <TabPanel value={currentTab} index={0}>
          <Grid container spacing={3}>
            {/* Current Framework */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: 'grey.50' }}>
                <Typography variant="h6" gutterBottom>
                  {t('trustRegistry.overview.activeFramework')}
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
                  {t('trustRegistry.overview.changeFramework')}
                </Button>
              </Paper>
            </Grid>

            {/* Quick Stats */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: 'grey.50' }}>
                <Typography variant="h6" gutterBottom>
                  {t('trustRegistry.overview.trustStatus')}
                </Typography>
                {!trustProfile || !healthStatus ? (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    {t('trustRegistry.overview.notConfiguredYet')}
                  </Alert>
                ) : (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2">{t('trustRegistry.overview.chainStatus')}</Typography>
                      <Chip
                        label={healthStatus?.chainStatus?.healthy ? t('trustRegistry.overview.healthy') : t('trustRegistry.overview.pending')}
                        size="small"
                        color={healthStatus?.chainStatus?.healthy ? 'success' : 'default'}
                      />
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2">{t('trustRegistry.overview.allChecks')}</Typography>
                      <Chip
                        label={healthStatus?.allPassed ? t('trustRegistry.overview.passed') : t('trustRegistry.overview.pendingSetup')}
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
                      {t('trustRegistry.overview.refreshStatus')}
                    </Button>
                  </Box>
                )}
              </Paper>
            </Grid>

            {/* Health Checklist */}
            <Grid item xs={12}>
              <Typography variant="h6" gutterBottom>
                {t('trustRegistry.overview.healthChecks')}
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
            {t('trustRegistry.frameworks.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            {t('trustRegistry.frameworks.description')}
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
                  t={t}
                />
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Tab 2: Certificate Chain */}
        <TabPanel value={currentTab} index={2}>
          <Typography variant="h6" gutterBottom>
            {t('trustRegistry.certificates.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            {t('trustRegistry.certificates.description')}
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
                {t('trustRegistry.certificates.warnings')}
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
                {t('trustRegistry.certificates.errors')}
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
            {t('trustRegistry.keys.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            {t('trustRegistry.keys.description')}
          </Typography>

          <Alert severity="info">
            <Typography variant="body2">
              {t('trustRegistry.keys.comingSoon')}
            </Typography>
          </Alert>

          {trustProfile?.verifierKeys && trustProfile.verifierKeys.length > 0 && (
            <Paper sx={{ p: 3, mt: 3 }}>
              <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                {t('trustRegistry.keys.verifierKeys')}
              </Typography>
              {trustProfile.verifierKeys.map((key, index) => (
                <Box key={index} sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>{t('trustRegistry.keys.location')}</strong> {key.location || t('trustRegistry.keys.notSpecified')}
                  </Typography>
                  <Typography variant="body2">
                    <strong>{t('trustRegistry.keys.certificate')}</strong> {key.hasCertificate ? t('trustRegistry.keys.attached') : t('trustRegistry.keys.notAttached')}
                  </Typography>
                  <Divider sx={{ mt: 1 }} />
                </Box>
              ))}
            </Paper>
          )}

          {trustProfile?.issuerKeys && trustProfile.issuerKeys.length > 0 && (
            <Paper sx={{ p: 3, mt: 3 }}>
              <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                {t('trustRegistry.keys.issuerKeys')}
              </Typography>
              {trustProfile.issuerKeys.map((key, index) => (
                <Box key={index} sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>{t('trustRegistry.keys.location')}</strong> {key.location || t('trustRegistry.keys.notSpecified')}
                  </Typography>
                  <Typography variant="body2">
                    <strong>{t('trustRegistry.keys.certificate')}</strong> {key.hasCertificate ? t('trustRegistry.keys.attached') : t('trustRegistry.keys.notAttached')}
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
