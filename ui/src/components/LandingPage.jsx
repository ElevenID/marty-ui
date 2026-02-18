/**
 * Landing Page Component
 *
 * Public landing page shown to unauthenticated users.
 * Provides information about the service, pricing tiers, and prompts login.
 */

import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { SEOHead, organizationSchema } from './seo';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Alert,
  Snackbar,
  CircularProgress,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
} from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import SecurityIcon from '@mui/icons-material/Security';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';
import { 
  IDENTITY_CONCEPTS, 
  PRODUCTS, 
  TRUST_SIGNALS,
  ORGANIZATION_OUTCOMES,
  AUDIENCE_ROUTING,
  PROOF_STRIP,
} from '../data/marketingContent';
import { UnifiedIdentityFlowDiagram, StandardsStackDiagram } from './diagrams';

function LandingPage() {
  const { t } = useTranslation('marketing');
  const brandingContext = useBranding();
  const branding = brandingContext?.branding || { appName: 'ElevenID LLC' };
  const { isAuthenticated, isLoading, register } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [authError, setAuthError] = useState(null);

  // Check for auth error in URL params
  useEffect(() => {
    const error = searchParams.get('auth_error');
    if (error) {
      setAuthError(decodeURIComponent(error.replace(/\+/g, ' ')));
      // Clear the error from URL without triggering navigation
      searchParams.delete('auth_error');
      setSearchParams(searchParams, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  // Redirect authenticated users to applicant console (person-first default)
  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      navigate('/console/applicant', { replace: true });
    }
  }, [isAuthenticated, isLoading, navigate]);

  const handleCloseError = () => {
    setAuthError(null);
  };

  // Show loading spinner while checking auth instead of blank page
  if (isLoading) {
    return (
      <>
        <SEOHead
          title="Verifiable Identity Infrastructure"
          description="Build verifiable identity infrastructure for EUDI Wallets, Open Badges, and W3C Verifiable Credentials. Issuance, verification, and trust governance APIs."
          canonicalPath="/"
          structuredData={organizationSchema()}
          keywords={[
            'verifiable credentials',
            'digital wallet',
            'EUDI Wallet',
            'Open Badges',
            'W3C VC',
            'identity verification',
            'ISO 18013-5',
            'mDL',
            'SD-JWT',
            'OID4VP',
          ]}
        />
        <Box 
          display="flex" 
          justifyContent="center" 
          alignItems="center" 
          minHeight="50vh"
          flexDirection="column"
          gap={2}
        >
          <CircularProgress />
          <Typography color="text.secondary">{t('landingPage.loading', 'Loading...')}</Typography>
        </Box>
      </>
    );
  }

  const features = [
    {
      icon: <FlightTakeoffIcon sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: t('landingPage.features.issuance.title', 'Issuance'),
      description: t(
        'landingPage.features.issuance.description',
        'Issue standards-based credentials with cryptographic signatures and policy enforcement.'
      ),
    },
    {
      icon: <VerifiedUserIcon sx={{ fontSize: 48, color: 'success.main' }} />,
      title: t('landingPage.features.verification.title', 'Verification'),
      description: t(
        'landingPage.features.verification.description',
        'Verify credentials against trust anchors with revocation checking and selective disclosure.'
      ),
    },
    {
      icon: <SecurityIcon sx={{ fontSize: 48, color: 'warning.main' }} />,
      title: t('landingPage.features.governance.title', 'Governance'),
      description: t(
        'landingPage.features.governance.description',
        'Manage trust, policy, and deployment centrally—without changing verifier code.'
      ),
    },
  ];

  const idvTraditionalItems = [
    t('idvComparison.traditional.oneTimeChecks', 'One-time document checks'),
    t('idvComparison.traditional.vendorControlled', 'Vendor-controlled identity data'),
    t('idvComparison.traditional.biometric', 'Biometric decision outputs'),
    t('idvComparison.traditional.closedAPIs', 'Closed, proprietary APIs'),
    t('idvComparison.traditional.manualTrust', 'Manual trust configuration'),
    t('idvComparison.traditional.reVerification', 'Re-verification everywhere'),
  ];

  const idvElevenIdItems = [
    t('idvComparison.elevenid.reusable', 'Reusable verifiable credentials'),
    t('idvComparison.elevenid.holderControlled', 'Holder-controlled digital wallets'),
    t('idvComparison.elevenid.cryptographic', 'Cryptographic proofs'),
    t('idvComparison.elevenid.openStandards', 'Open standards (W3C VC, OID4VC, ISO)'),
    t('idvComparison.elevenid.governedTrust', 'Governed trust registries'),
    t('idvComparison.elevenid.reuseAcross', 'Identity reuse across ecosystems'),
  ];

  const eudiPoints = [
    t('eudiOpenBadges.verifyCredentials', 'Verify Verifiable Credentials—not just documents.'),
    t('eudiOpenBadges.trustIssuers', 'Trust issuers—not databases.'),
    t('eudiOpenBadges.walletFirst', 'Wallet-first by design—EUDI-ready.'),
  ];

  const identityProblems = [
    t(
      'landingPage.identityProblem.items.fragmented',
      IDENTITY_CONCEPTS.whatIs.problems?.[0] || "Fragmented identity systems that don't interoperate"
    ),
    t(
      'landingPage.identityProblem.items.unclearTrust',
      IDENTITY_CONCEPTS.whatIs.problems?.[1] || 'Unclear issuer trust across partners and jurisdictions'
    ),
    t(
      'landingPage.identityProblem.items.privacyPressure',
      IDENTITY_CONCEPTS.whatIs.problems?.[2] || 'Privacy compliance pressure (data minimization + selective disclosure)'
    ),
    t(
      'landingPage.identityProblem.items.pkiComplexity',
      IDENTITY_CONCEPTS.whatIs.problems?.[3] || 'PKI + revocation complexity at scale'
    ),
  ];

  const organizationOutcomes = [
    t('organizationOutcomes.reduceKYC', ORGANIZATION_OUTCOMES.outcomes?.[0] || 'Reduce repeat KYC costs with reusable credentials'),
    t('organizationOutcomes.eudiReady', ORGANIZATION_OUTCOMES.outcomes?.[1] || 'Prepare for EUDI Wallet acceptance'),
    t('organizationOutcomes.avoidLockIn', ORGANIZATION_OUTCOMES.outcomes?.[2] || 'Avoid vendor lock-in with open standards'),
    t('organizationOutcomes.supportBadges', ORGANIZATION_OUTCOMES.outcomes?.[3] || 'Support Open Badges, workforce credentials, and government IDs in one system'),
  ];

  const trustSignals = {
    security: [
      t('landingPage.trustSignals.security.item1', TRUST_SIGNALS.security?.[0] || 'Enterprise-grade cryptographic validation'),
      t('landingPage.trustSignals.security.item2', TRUST_SIGNALS.security?.[1] || 'PKI and revocation management'),
      t('landingPage.trustSignals.security.item3', TRUST_SIGNALS.security?.[2] || 'HSM and key vault integration'),
    ],
    infrastructure: [
      t('landingPage.trustSignals.infrastructure.item1', TRUST_SIGNALS.infrastructure?.[0] || 'Offline-first capability (72h cache)'),
      t('landingPage.trustSignals.infrastructure.item2', TRUST_SIGNALS.infrastructure?.[1] || 'High-availability SaaS deployment'),
      t('landingPage.trustSignals.infrastructure.item3', TRUST_SIGNALS.infrastructure?.[2] || 'Self-hosted options for sovereignty'),
      t('landingPage.trustSignals.infrastructure.item4', TRUST_SIGNALS.infrastructure?.[3] || 'Horizontal scaling and load balancing'),
      t('landingPage.trustSignals.infrastructure.item5', TRUST_SIGNALS.infrastructure?.[4] || 'Built with AI-assisted development workflows to maintain high quality at lower cost.'),
    ],
    compliance: [
      t('landingPage.trustSignals.compliance.item1', TRUST_SIGNALS.compliance?.[0] || 'Implements ICAO 9303'),
      t('landingPage.trustSignals.compliance.item2', TRUST_SIGNALS.compliance?.[1] || 'Implements ISO 18013-5 (mDoc)'),
      t('landingPage.trustSignals.compliance.item3', TRUST_SIGNALS.compliance?.[2] || 'GDPR and privacy by design'),
      t('landingPage.trustSignals.compliance.item4', TRUST_SIGNALS.compliance?.[3] || 'Selective disclosure and data minimization'),
    ],
  };

  const proofClaims = [
    {
      category: t('proofStrip.interoperability', 'Interoperability'),
      label: t('landingPage.proofStrip.claims.w3c', PROOF_STRIP.claims?.[0]?.label || 'W3C VC / SD-JWT / OID4VP'),
    },
    {
      category: t('proofStrip.offlineVerification', 'Offline Verification'),
      label: t('landingPage.proofStrip.claims.offlineCache', PROOF_STRIP.claims?.[1]?.label || '72-hour offline cache'),
    },
    {
      category: t('proofStrip.deployment', 'Deployment'),
      label: t('landingPage.proofStrip.claims.deployment', PROOF_STRIP.claims?.[2]?.label || 'SaaS + Self-hosted'),
    },
    {
      category: t('proofStrip.keySecurity', 'Key Security'),
      label: t('landingPage.proofStrip.claims.keySecurity', PROOF_STRIP.claims?.[3]?.label || 'HSM / Vault integration'),
    },
    {
      category: t('proofStrip.compliance', 'Compliance'),
      label: t('landingPage.proofStrip.claims.auditLogs', PROOF_STRIP.claims?.[4]?.label || 'Immutable audit logs'),
    },
  ];

  return (
    <Box>
      {/* SEO Meta Tags */}
      <SEOHead
        title="Verifiable Identity Infrastructure"
        description="Build verifiable identity infrastructure for EUDI Wallets, Open Badges, and W3C Verifiable Credentials. Issuance, verification, and trust governance APIs."
        canonicalPath="/"
        structuredData={organizationSchema()}
        keywords={[
          'verifiable credentials',
          'digital wallet',
          'EUDI Wallet',
          'Open Badges',
          'W3C VC',
          'identity verification',
          'ISO 18013-5',
          'mDL',
          'SD-JWT',
          'OID4VP',
        ]}
      />
      
      {/* Auth Error Snackbar */}
      <Snackbar
        open={!!authError}
        autoHideDuration={10000}
        onClose={handleCloseError}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert 
          onClose={handleCloseError} 
          severity="warning" 
          variant="filled"
          sx={{ width: '100%' }}
        >
          {authError}
        </Alert>
      </Snackbar>

      {/* Hero Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 8,
          background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
          color: 'white',
          borderRadius: 2,
          mb: 4,
        }}
      >
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          {t('valueProposition.headline', 'Verifiable Identity Infrastructure')}
        </Typography>
        <Typography variant="h5" sx={{ mb: 2, opacity: 0.90, maxWidth: 900, mx: 'auto', fontStyle: 'italic' }}>
          {t('valueProposition.provocative', 'Identity verification is not enough.')}
        </Typography>
        <Typography variant="h4" sx={{ mb: 2, opacity: 0.95, maxWidth: 900, mx: 'auto' }}>
          {t('valueProposition.subheadline', 'Build verifiable identity infrastructure.')}
        </Typography>
        <Typography variant="h6" sx={{ mb: 4, opacity: 0.85, maxWidth: 800, mx: 'auto' }}>
          {t('valueProposition.extendedSubheadline', 'Issue, verify, and govern credentials—built for EUDI Wallets, Open Badges, and enterprise trust.')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<LoginIcon />}
            onClick={() => register()}
            data-testid="get-started-btn"
            sx={{
              bgcolor: 'white',
              color: 'primary.main',
              '&:hover': { bgcolor: 'grey.100' },
              px: 4,
              py: 1.5,
            }}
          >
            {t('valueProposition.primaryCTA', 'Start Free')}
          </Button>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/from-idv-to-verifiable-identity"
            endIcon={<ArrowForwardIcon />}
            sx={{
              borderColor: 'white',
              color: 'white',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', borderColor: 'white' },
              px: 4,
              py: 1.5,
            }}
          >
            {t('valueProposition.secondaryCTA', 'Why Verifiable Identity')} →
          </Button>
        </Box>
      </Box>

      {/* IDV Comparison Section */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('idvComparison.title', 'From IDV to Verifiable Identity')}
        </Typography>
        <Grid container spacing={3} sx={{ mt: 2 }}>
          <Grid item xs={12} md={6}>
            <Paper elevation={2} sx={{ p: 3, height: '100%', bgcolor: 'grey.100' }}>
              <Typography variant="h6" fontWeight="bold" gutterBottom color="text.secondary">
                {t('idvComparison.traditional.title', 'Traditional IDV Platforms')}
              </Typography>
              <List>
                {idvTraditionalItems.map((item, index) => (
                  <ListItem key={index} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon fontSize="small" color="action" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={item}
                      primaryTypographyProps={{ variant: 'body2' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper elevation={3} sx={{ p: 3, height: '100%', bgcolor: 'primary.light', color: 'primary.contrastText' }}>
              <Typography variant="h6" fontWeight="bold" gutterBottom>
                {branding.appName}
              </Typography>
              <List>
                {idvElevenIdItems.map((item, index) => (
                  <ListItem key={index} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon fontSize="small" sx={{ color: 'success.light' }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={item}
                      primaryTypographyProps={{ variant: 'body2', fontWeight: 500 }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>
        <Typography 
          variant="h6" 
          textAlign="center" 
          sx={{ mt: 3, fontStyle: 'italic', color: 'primary.main' }}
        >
          {t('idvComparison.takeaway', 'ElevenID LLC replaces repeated verification with reusable trust.')}
        </Typography>
      </Box>

      {/* EUDI & Open Badges Section */}
      <Paper elevation={3} sx={{ p: 4, mb: 8, bgcolor: 'success.light', borderRadius: 2 }}>
        <Typography variant="h5" gutterBottom fontWeight="bold" color="success.dark">
          {t('eudiOpenBadges.title', 'Built for EUDI Wallets and Verifiable Credentials')}
        </Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {eudiPoints.map((point, index) => (
            <Grid item xs={12} sm={4} key={index}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon color="success" />
                <Typography variant="body1" fontWeight="500">
                  {point}
                </Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
        <Paper elevation={0} sx={{ p: 3, bgcolor: 'white', borderLeft: 4, borderColor: 'success.main' }}>
          <Typography variant="body1" sx={{ fontStyle: 'italic', fontSize: '1.05rem', lineHeight: 1.7 }}>
            &ldquo;{t('eudiOpenBadges.quote', 'IDV platforms stop at a one-time decision. ElevenID LLC produces cryptographically verifiable outcomes that can be reused across wallets, ecosystems, and trust registries.')}&rdquo;
          </Typography>
        </Paper>
      </Paper>

      {/* Audience Routing Block */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('audienceRouting.title', AUDIENCE_ROUTING.title)}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4 }}>
          {t('audienceRouting.subtitle', AUDIENCE_ROUTING.subtitle)}
        </Typography>
        <Grid container spacing={3}>
          {AUDIENCE_ROUTING.paths.map((path) => (
            <Grid item xs={12} md={4} key={path.id}>
              <Card 
                component="a"
                href={path.path}
                elevation={2} 
                sx={{ 
                  height: '100%', 
                  cursor: 'pointer',
                  textDecoration: 'none',
                  color: 'inherit',
                  transition: 'transform 0.2s, box-shadow 0.2s',
                  '&:hover': { 
                    transform: 'translateY(-4px)', 
                    boxShadow: 4 
                  },
                }}
              >
                <CardContent sx={{ textAlign: 'center', py: 4 }}>
                  <Typography variant="h5" fontWeight="bold" color={`${path.color}.main`} gutterBottom>
                    {t(`audienceRouting.${path.id}.title`, path.title)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3, minHeight: 60 }}>
                    {t(`audienceRouting.${path.id}.description`, path.description)}
                  </Typography>
                  <Button
                    variant="outlined"
                    component="a"
                    href={path.path}
                    color={path.color}
                    endIcon={<ArrowForwardIcon />}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {t(`audienceRouting.${path.id}.cta`, path.cta)}
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* The Identity Problem */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.identityProblem.title', 'The Identity Problem')}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 700, mx: 'auto' }}>
          {t(
            'landingPage.identityProblem.description',
            'Most organizations face fragmented systems, unclear trust, and growing compliance pressure.'
          )}
        </Typography>

        <Grid container spacing={3}>
          {identityProblems.map((problem, index) => (
            <Grid item xs={12} sm={6} key={index}>
              <Card elevation={2}>
                <CardContent>
                  <Typography variant="body1">
                    {problem}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* How ElevenID LLC Solves It */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.solvesIt.title', `How ${branding.appName} Solves It`)}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 2, maxWidth: 800, mx: 'auto' }}>
          {t(
            'landingPage.solvesIt.intro',
            'Govern identity with four primitives: trust profiles, credential templates, presentation policies, and flows.'
          )}
        </Typography>
        <Typography variant="body2" color="primary.main" textAlign="center" paragraph sx={{ mb: 4, fontWeight: 500 }}>
          {t(
            'landingPage.solvesIt.subheading',
            'Policies are configuration, not code. Endpoints execute centrally governed trust and disclosure rules without redeployment.'
          )}
        </Typography>

        <Grid container spacing={4}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={4} key={index}>
              <Card sx={{ height: '100%', textAlign: 'center' }}>
                <CardContent sx={{ py: 4 }}>
                  {feature.icon}
                  <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>
                    {feature.title}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    {feature.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* How It Works - Visual */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.howItWorks.title', 'How It Works')}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          {t(
            'landingPage.howItWorks.description',
            'Digital identity is a governed exchange between four actors.'
          )}
        </Typography>

        <Paper elevation={3} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <UnifiedIdentityFlowDiagram interactive={true} />
        </Paper>

        <Box sx={{ textAlign: 'center', mt: 3 }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/identity"
            endIcon={<ArrowForwardIcon />}
          >
            {t('landingPage.howItWorks.cta', 'See the Full Flow')} →
          </Button>
        </Box>
      </Box>

      {/* Why This Matters for Organizations */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('organizationOutcomes.title', ORGANIZATION_OUTCOMES.title)}
        </Typography>
        <Grid container spacing={3} sx={{ mt: 2 }}>
          {organizationOutcomes.map((outcome, index) => (
            <Grid item xs={12} sm={6} key={index}>
              <Card elevation={2}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'start', gap: 1 }}>
                    <CheckCircleIcon color="success" sx={{ mt: 0.5 }} />
                    <Typography variant="body1">
                      {outcome}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* Standards & Interoperability */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.standards.title', 'Standards-Based Architecture')}
        </Typography>
        <Typography 
          variant="h6" 
          textAlign="center" 
          sx={{ mb: 4, fontWeight: 500, color: 'primary.main' }}
        >
          {t('landingPage.standards.subtitle', 'Standards are not integrations. They are the product.')}
        </Typography>

        <Paper elevation={3} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <StandardsStackDiagram interactive={false} />
        </Paper>

        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mt: 3, mb: 2, maxWidth: 700, mx: 'auto' }}>
          {t(
            'landingPage.standards.description',
            "These layers let ElevenID LLC interoperate across governments, wallets, and enterprises without custom integrations."
          )}
        </Typography>

        <Box sx={{ textAlign: 'center' }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/standards"
            endIcon={<ArrowForwardIcon />}
          >
            {t('landingPage.standards.cta', 'Explore Standards')}
          </Button>
        </Box>
      </Box>

      {/* What to buy first? - Product on-ramp */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.startFirst.title', 'What are you doing first?')}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 600, mx: 'auto' }}>
          {t(
            'landingPage.startFirst.description',
            "Choose a starting point. You can expand into a full ecosystem when you're ready."
          )}
        </Typography>
        <Grid container spacing={2} justifyContent="center">
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/verifiable-credential-api"
              elevation={2} 
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 3 }}>
                <VerifiedUserIcon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  {t('landingPage.startFirst.cards.verify.title', 'Verify Verifiable Credentials')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(
                    'landingPage.startFirst.cards.verify.description',
                    'Verify EUDI wallets, Open Badges, and ISO credentials.'
                  )}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/open-badges-issuance"
              elevation={2}
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 3 }}>
                <FlightTakeoffIcon sx={{ fontSize: 40, color: 'secondary.main', mb: 1 }} />
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  {t('landingPage.startFirst.cards.issue.title', 'Issue Open Badges Credentials')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(
                    'landingPage.startFirst.cards.issue.description',
                    'Issue workforce, education, or government credentials.'
                  )}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/iso-18013-5-mdoc-verification"
              elevation={2}
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 3 }}>
                <SecurityIcon sx={{ fontSize: 40, color: 'warning.main', mb: 1 }} />
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  {t('landingPage.startFirst.cards.offline.title', 'ISO 18013-5 Offline Verification')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(
                    'landingPage.startFirst.cards.offline.description',
                    'Verify at checkpoints with limited connectivity.'
                  )}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/eudi-wallet-verification"
              elevation={2}
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 3 }}>
                <LoginIcon sx={{ fontSize: 40, color: 'info.main', mb: 1 }} />
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  {t('landingPage.startFirst.cards.wallet.title', 'EUDI Wallet Verification')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(
                    'landingPage.startFirst.cards.wallet.description',
                    'Give users a wallet to hold and present credentials.'
                  )}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mt: 2 }}>
          {t('landingPage.startFirst.notSure', 'Not sure?')}{' '}
          <Typography 
            component="a" 
            href="/verifiable-credential-api"
            sx={{ color: 'primary.main', cursor: 'pointer', textDecoration: 'underline' }}
          >
            {t('landingPage.startFirst.startWithVerificationApi', 'Start with Verification API')} →
          </Typography>
        </Typography>
      </Box>

      {/* Products & Capabilities */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.products.title', 'Products & Capabilities')}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          {t('landingPage.products.description', 'A complete platform—from issuance to verification and governance.')}
        </Typography>

        <Grid container spacing={3}>
          {PRODUCTS.slice(0, 4).map((product) => (
            <Grid item xs={12} sm={6} md={3} key={product.id}>
              <Card elevation={2} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <CardContent sx={{ flexGrow: 1 }}>
                  <Typography variant="h6" fontWeight="bold" gutterBottom>
                    {product.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {product.tagline}
                  </Typography>
                  {product.replacesExtends && (
                    <Typography variant="body2" sx={{ mb: 1, fontStyle: 'italic', color: 'primary.main' }}>
                      {product.replacesExtends}
                    </Typography>
                  )}
                  {product.useWhen && (
                    <Typography variant="body2" sx={{ mb: 2, color: 'text.secondary', fontSize: '0.8rem' }}>
                      {product.useWhen}
                    </Typography>
                  )}
                  <Box sx={{ mb: 2 }}>
                    {product.deployment.slice(0, 2).map((deploy) => (
                      <Chip
                        key={deploy}
                        label={deploy}
                        size="small"
                        variant="outlined"
                        sx={{ mr: 0.5, mb: 0.5 }}
                      />
                    ))}
                  </Box>
                </CardContent>
                <Box sx={{ p: 2, pt: 0 }}>
                  <Button
                    size="small"
                    fullWidth
                    variant="text"
                    component="a"
                    href="/product"
                    endIcon={<ArrowForwardIcon fontSize="small" />}
                    sx={{ justifyContent: 'flex-start' }}
                  >
                    {t('landingPage.products.viewDetails', 'View Details')}
                  </Button>
                </Box>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ textAlign: 'center', mt: 3 }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/product"
            endIcon={<ArrowForwardIcon />}
          >
            {t('landingPage.products.viewAll', 'View All Products')}
          </Button>
        </Box>
      </Box>

      {/* Trust Signals */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {t('landingPage.trustSignals.title', 'Enterprise-Grade Infrastructure')}
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
                  {t('landingPage.trustSignals.security.title', 'Security')}
                </Typography>
                <List dense>
                  {trustSignals.security.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon fontSize="small" color="success" />
                      </ListItemIcon>
                      <ListItemText 
                        primary={item}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="secondary" gutterBottom>
                  {t('landingPage.trustSignals.infrastructure.title', 'Infrastructure')}
                </Typography>
                <List dense>
                  {trustSignals.infrastructure.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon fontSize="small" color="success" />
                      </ListItemIcon>
                      <ListItemText 
                        primary={item}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="success.main" gutterBottom>
                  {t('landingPage.trustSignals.compliance.title', 'Compliance')}
                </Typography>
                <List dense>
                  {trustSignals.compliance.map((item) => (
                    <ListItem key={item} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon fontSize="small" color="success" />
                      </ListItemIcon>
                      <ListItemText 
                        primary={item}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Proof & Credibility Strip */}
      <Paper 
        elevation={0} 
        sx={{ 
          mb: 8, 
          p: 3, 
          bgcolor: 'grey.50', 
          borderRadius: 2,
          border: '1px solid',
          borderColor: 'grey.200'
        }}
      >
        <Typography variant="subtitle1" fontWeight="bold" textAlign="center" sx={{ mb: 2 }}>
          {t('proofStrip.title', PROOF_STRIP.title)}
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 2 }}>
          {proofClaims.map((claim) => (
            <Chip
              key={`${claim.category}:${claim.label}`}
              label={`${claim.category}: ${claim.label}`}
              variant="outlined"
              sx={{ borderColor: 'grey.400' }}
            />
          ))}
        </Box>
      </Paper>

      {/* User Type Info - Condensed */}
      <Paper 
        elevation={0} 
        sx={{ 
          mb: 8, 
          p: 2, 
          bgcolor: 'grey.50', 
          borderRadius: 1,
          textAlign: 'center'
        }}
      >
        <Typography variant="body2" color="text.secondary">
          <strong>{t('landingPage.portals.emphasis', 'Built-in portals')}</strong>{' '}
          {t(
            'landingPage.portals.message',
            'for applicants, vendors, and admins—manage API keys, trust policies, and operations in one place.'
          )}{' '}
          <Typography
            component="a"
            href="/product"
            sx={{
              color: 'primary.main',
              textDecoration: 'underline',
              cursor: 'pointer',
              '&:hover': { color: 'primary.dark' }
            }}
          >
            {t('landingPage.portals.learnMore', 'Learn more')} →
          </Typography>
        </Typography>
      </Paper>

      {/* Footer CTA */}
      <Box 
        sx={{ 
          textAlign: 'center', 
          py: 6, 
          bgcolor: 'grey.100', 
          borderRadius: 2,
        }}
      >
        <Typography variant="h4" gutterBottom fontWeight="bold">
          {t('landingPage.footer.title', 'Ready to get started?')}
        </Typography>
        <Typography variant="body1" color="textSecondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
          {t('landingPage.footer.description', 'Start free, or compare plans for your organization.')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<LoginIcon />}
            onClick={() => register()}
            sx={{ px: 4 }}
          >
            {t('valueProposition.primaryCTA', 'Start Free')}
          </Button>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/pricing"
            sx={{ px: 4 }}
          >
            {t('landingPage.footer.viewPricing', 'View Pricing')}
          </Button>
        </Box>
      </Box>

      {/* Orientation Banner */}
      <Box 
        sx={{ 
          mt: 6, 
          p: 2, 
          bgcolor: 'grey.50', 
          borderRadius: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 1
        }}
      >
        <Typography variant="body2" color="text.secondary">
          <strong>{t('landingPage.orientation.title', 'New to verifiable identity?')}</strong>
        </Typography>
        <Button
          size="small"
          component="a"
          href="/identity"
          endIcon={<ArrowForwardIcon fontSize="small" />}
          sx={{ textTransform: 'none' }}
        >
          {t('landingPage.orientation.cta', 'How It Works')}
        </Button>
      </Box>
    </Box>
  );
}

export default LandingPage;
