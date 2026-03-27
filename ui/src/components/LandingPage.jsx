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
  CardActionArea,
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
  Divider,
  Collapse,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import SecurityIcon from '@mui/icons-material/Security';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import BusinessIcon from '@mui/icons-material/Business';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import CodeIcon from '@mui/icons-material/Code';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import GppGoodIcon from '@mui/icons-material/GppGood';
import GavelIcon from '@mui/icons-material/Gavel';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import ApiIcon from '@mui/icons-material/Api';
import PhoneIphoneIcon from '@mui/icons-material/PhoneIphone';
import SettingsInputAntennaIcon from '@mui/icons-material/SettingsInputAntenna';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';
import {
  clearLandingAuthError,
  getLandingAuthError,
  getLandingEntryDecision,
} from '../application/routing';
import GitHubIcon from '@mui/icons-material/GitHub';
import { 
  IDENTITY_CONCEPTS, 
  PRODUCTS, 
  TRUST_SIGNALS,
  ORGANIZATION_OUTCOMES,
  AUDIENCE_ROUTING,
  PROOF_STRIP,
  VALUE_PROPOSITION,
  STANDARDS_INFO,
  PROTOCOL,
  BLOG_POSTS,
} from '../data/marketingContent';
import {
  GUIDE_CHAPTERS,
  GUIDE_ARTICLES_BY_CHAPTER,
} from '../data/guideContent';
import { UnifiedIdentityFlowDiagram, StandardsStackDiagram, InteractiveProtocolMap } from './diagrams';

// Fade-in animation style helper
const fadeInSx = (delay = 0) => ({
  '@keyframes fadeInUp': {
    from: { opacity: 0, transform: 'translateY(24px)' },
    to: { opacity: 1, transform: 'translateY(0)' },
  },
  animation: `fadeInUp 0.6s ease-out ${delay}s both`,
});

// Section wrapper with alternating backgrounds and increased spacing
function Section({ children, bgcolor, sx, ...rest }) {
  return (
    <Box
      sx={{
        py: { xs: 6, md: 10 },
        px: { xs: 2, md: 0 },
        bgcolor: bgcolor || 'transparent',
        ...sx,
      }}
      {...rest}
    >
      {children}
    </Box>
  );
}

// Section heading
function SectionHeading({ children, subtitle, divider, sx }) {
  return (
    <Box sx={{ textAlign: 'center', mb: 5, ...sx }}>
      {divider && <Divider sx={{ mb: 3, maxWidth: 80, mx: 'auto', borderWidth: 2, borderColor: 'primary.main' }} />}
      <Typography variant="h4" component="h2" fontWeight={800} gutterBottom sx={{ fontSize: { xs: '1.75rem', md: '2.25rem' } }}>
        {children}
      </Typography>
      {subtitle && (
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 700, mx: 'auto' }}>
          {subtitle}
        </Typography>
      )}
    </Box>
  );
}

// Audience path icon mapping
const AUDIENCE_ICONS = {
  Business: <BusinessIcon sx={{ fontSize: 40 }} />,
  AccountBalance: <AccountBalanceIcon sx={{ fontSize: 40 }} />,
  Code: <CodeIcon sx={{ fontSize: 40 }} />,
};

// Product icon mapping
const PRODUCT_ICONS = {
  'verification-api': <ApiIcon sx={{ fontSize: 36, color: 'primary.main' }} />,
  'issuance-api': <FlightTakeoffIcon sx={{ fontSize: 36, color: 'secondary.main' }} />,
  'kiosk': <SettingsInputAntennaIcon sx={{ fontSize: 36, color: 'warning.main' }} />,
  'authenticator': <PhoneIphoneIcon sx={{ fontSize: 36, color: 'info.main' }} />,
};

function LandingPage() {
  const { t } = useTranslation('marketing');
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const brandingContext = useBranding();
  const branding = brandingContext?.branding || { appName: 'ElevenID LLC' };
  const { isAuthenticated, isLoading, register } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [authError, setAuthError] = useState(null);
  const [expandedLayer, setExpandedLayer] = useState(null);

  // Check for auth error in URL params
  useEffect(() => {
    const error = getLandingAuthError(searchParams);
    if (error) {
      setAuthError(error);
      setSearchParams(clearLandingAuthError(searchParams), { replace: true });
    }
  }, [searchParams, setSearchParams]);

  // Redirect authenticated users to applicant console (person-first default)
  useEffect(() => {
    const decision = getLandingEntryDecision({ isAuthenticated, isLoading });
    if (decision.action === 'navigate' && decision.redirectTo) {
      navigate(decision.redirectTo, { replace: true });
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

  // Identity problems grouped into 3 themes
  const identityProblemThemes = [
    {
      icon: <SyncAltIcon sx={{ fontSize: 36, color: 'error.main' }} />,
      theme: t('landingPage.identityProblem.themes.interoperability', 'Interoperability'),
      problems: [
        t('landingPage.identityProblem.items.fragmented', "Fragmented systems that don't interoperate across partners or jurisdictions"),
      ],
    },
    {
      icon: <GppGoodIcon sx={{ fontSize: 36, color: 'warning.main' }} />,
      theme: t('landingPage.identityProblem.themes.trust', 'Trust'),
      problems: [
        t('landingPage.identityProblem.items.unclearTrust', 'Unclear issuer trust and PKI complexity at scale'),
      ],
    },
    {
      icon: <GavelIcon sx={{ fontSize: 36, color: 'info.main' }} />,
      theme: t('landingPage.identityProblem.themes.compliance', 'Compliance'),
      problems: [
        t('landingPage.identityProblem.items.privacyPressure', 'Privacy pressure—data minimization and selective disclosure requirements'),
      ],
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
    { text: t('idvComparison.elevenid.reusable', 'Reusable verifiable credentials'), bold: 'Reusable credentials' },
    { text: t('idvComparison.elevenid.holderControlled', 'Holder-controlled digital wallets'), bold: null },
    { text: t('idvComparison.elevenid.cryptographic', 'Cryptographic proofs'), bold: 'Cryptographic proofs' },
    { text: t('idvComparison.elevenid.openStandards', 'Open standards (W3C VC, OID4VC, ISO)'), bold: null },
    { text: t('idvComparison.elevenid.governedTrust', 'Governed trust registries'), bold: null },
    { text: t('idvComparison.elevenid.reuseAcross', 'Identity reuse across ecosystems'), bold: null },
  ];

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
    ],
    compliance: [
      t('landingPage.trustSignals.compliance.item1', TRUST_SIGNALS.compliance?.[0] || 'Implements ICAO 9303'),
      t('landingPage.trustSignals.compliance.item2', TRUST_SIGNALS.compliance?.[1] || 'Implements ISO 18013-5 (mDoc)'),
      t('landingPage.trustSignals.compliance.item3', TRUST_SIGNALS.compliance?.[2] || 'GDPR and privacy by design'),
      t('landingPage.trustSignals.compliance.item4', TRUST_SIGNALS.compliance?.[3] || 'Selective disclosure and data minimization'),
    ],
  };

  return (
    <Box sx={{ scrollBehavior: 'smooth' }}>
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
          'Marty Identity Protocol',
          'MIP',
          'open standard',
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

      {/* ───────────────────────────────────────────────────────────  HERO  */}
      <Box
        sx={{
          textAlign: 'center',
          py: { xs: 6, md: 10 },
          px: { xs: 2, md: 4 },
          background: 'linear-gradient(135deg, #1976d2 0%, #0d47a1 100%)',
          color: 'white',
          borderRadius: 2,
          mb: 0,
          ...fadeInSx(0),
        }}
      >
        <Typography
          variant="h3"
          component="h1"
          gutterBottom
          fontWeight={800}
          sx={{ fontSize: { xs: '2rem', md: '3rem' }, lineHeight: 1.15 }}
        >
          {t('valueProposition.headline', VALUE_PROPOSITION.headline)}
        </Typography>
        <Typography
          variant="h6"
          sx={{ mb: 2, opacity: 0.88, maxWidth: 720, mx: 'auto', fontStyle: 'italic', fontWeight: 400 }}
        >
          {t('valueProposition.supporting', VALUE_PROPOSITION.supportingSubheadline)}
        </Typography>
        <Typography
          variant="h5"
          sx={{ mb: 1, opacity: 0.95, maxWidth: 900, mx: 'auto', fontWeight: 600 }}
        >
          {t('valueProposition.subheadline', VALUE_PROPOSITION.subheadline)}
        </Typography>
        <Typography variant="body1" sx={{ mb: 4, opacity: 0.82, maxWidth: 800, mx: 'auto' }}>
          {t('valueProposition.extendedSubheadline', VALUE_PROPOSITION.extendedSubheadline)}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<VerifiedUserIcon />}
            onClick={() => register()}
            data-testid="get-started-btn"
            sx={{
              bgcolor: 'white',
              color: 'primary.main',
              fontWeight: 700,
              '&:hover': { bgcolor: 'grey.100', transform: 'translateY(-2px)', boxShadow: 4 },
              px: { xs: 3, md: 4 },
              py: 1.5,
              width: { xs: '100%', sm: 'auto' },
              transition: 'all 0.2s ease',
            }}
          >
            {t('valueProposition.primaryCTA', VALUE_PROPOSITION.primaryCTA)}
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
              fontWeight: 600,
              '&:hover': { bgcolor: 'rgba(255,255,255,0.12)', borderColor: 'white', transform: 'translateY(-2px)' },
              px: { xs: 3, md: 4 },
              py: 1.5,
              width: { xs: '100%', sm: 'auto' },
              transition: 'all 0.2s ease',
            }}
          >
            {t('valueProposition.secondaryCTA', 'Why Verifiable Identity')}
          </Button>
        </Box>
      </Box>

      {/* ─── Trust signal strip right below hero ─── */}
      <Paper
        elevation={0}
        sx={{
          py: 2,
          px: 2,
          mb: 0,
          bgcolor: 'grey.900',
          color: 'grey.300',
          borderRadius: 0,
          textAlign: 'center',
        }}
      >
        <Typography variant="caption" fontWeight={600} sx={{ letterSpacing: 1.5, textTransform: 'uppercase', mr: 2 }}>
          Standards-aligned
        </Typography>
        {['W3C VC', 'ISO 18013-5', 'OpenID4VP', 'SD-JWT', 'ICAO 9303', 'eIDAS 2.0'].map((s) => (
          <Chip
            key={s}
            label={s}
            size="small"
            sx={{ mr: 1, mb: { xs: 0.5, md: 0 }, bgcolor: 'rgba(255,255,255,0.08)', color: 'grey.300', fontSize: '0.7rem' }}
          />
        ))}
      </Paper>

      {/* ─── Concrete example ─── */}
      <Box sx={{ textAlign: 'center', py: 3, px: 2, bgcolor: 'primary.50' }}>
        <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', maxWidth: 700, mx: 'auto' }}>
          {t('valueProposition.concreteExample', VALUE_PROPOSITION.concreteExample)}
        </Typography>
      </Box>

      {/* ───────────────────────────────────────  IDV COMPARISON (side-by-side table) */}
      <Section bgcolor="grey.50">
        <Typography
          variant="body1"
          color="text.secondary"
          fontStyle="italic"
          textAlign="center"
          sx={{ mb: 3 }}
        >
          So what breaks in today&apos;s systems?
        </Typography>
        <SectionHeading
          subtitle={t('idvComparison.takeaway', 'ElevenID LLC replaces repeated verification with reusable trust.')}
          divider
        >
          {t('idvComparison.title', 'From IDV to Verifiable Identity')}
        </SectionHeading>

        <Grid container spacing={3} sx={{ maxWidth: 900, mx: 'auto' }}>
          {/* Traditional column */}
          <Grid item xs={12} md={6}>
            <Paper
              elevation={0}
              sx={{
                p: 3,
                height: '100%',
                bgcolor: 'white',
                border: '1px solid',
                borderColor: 'grey.300',
                borderRadius: 2,
              }}
            >
              <Typography variant="h6" fontWeight={700} gutterBottom color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CancelIcon color="error" /> {t('idvComparison.traditional.title', 'Traditional IDV')}
              </Typography>
              <List disablePadding>
                {idvTraditionalItems.map((item, index) => (
                  <ListItem key={index} sx={{ py: 0.75, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CancelIcon fontSize="small" sx={{ color: 'error.light' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={item}
                      primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          {/* ElevenID column */}
          <Grid item xs={12} md={6}>
            <Paper
              elevation={3}
              sx={{
                p: 3,
                height: '100%',
                bgcolor: 'primary.main',
                color: 'primary.contrastText',
                borderRadius: 2,
              }}
            >
              <Typography variant="h6" fontWeight={700} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon sx={{ color: 'success.light' }} /> {branding.appName}
              </Typography>
              <List disablePadding>
                {idvElevenIdItems.map((item, index) => (
                  <ListItem key={index} sx={{ py: 0.75, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" sx={{ color: 'success.light' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        item.bold ? (
                          <span>
                            <strong>{item.bold}</strong>
                            {item.text.replace(item.bold, '').replace(/^[—–-]\s*/, '')}
                          </span>
                        ) : item.text
                      }
                      primaryTypographyProps={{ variant: 'body2', fontWeight: 500 }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* CTA after comparison */}
        <Box sx={{ textAlign: 'center', mt: 4 }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/from-idv-to-verifiable-identity"
            endIcon={<ArrowForwardIcon />}
            sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
          >
            {t('idvComparison.cta', 'See how verification works')}
          </Button>
        </Box>
      </Section>

      {/* ───────────────────────────────────  THE IDENTITY PROBLEM (3 themes)  */}
      <Section>
        <Typography
          variant="body1"
          color="text.secondary"
          fontStyle="italic"
          textAlign="center"
          sx={{ mb: 3 }}
        >
          So what breaks in today&apos;s identity systems?
        </Typography>
        <SectionHeading
          subtitle={t(
            'landingPage.identityProblem.description',
            'Most organizations face fragmented systems, unclear trust, and growing compliance pressure.'
          )}
          divider
        >
          {t('landingPage.identityProblem.title', 'The Identity Problem')}
        </SectionHeading>

        <Grid container spacing={4} sx={{ maxWidth: 960, mx: 'auto' }}>
          {identityProblemThemes.map((group, index) => (
            <Grid item xs={12} md={4} key={index}>
              <Card
                elevation={2}
                sx={{
                  height: '100%',
                  textAlign: 'center',
                  transition: 'all 0.2s ease',
                  '&:hover': { transform: 'translateY(-4px)', boxShadow: 6 },
                }}
              >
                <CardContent sx={{ py: 4 }}>
                  {group.icon}
                  <Typography variant="h6" fontWeight={700} sx={{ mt: 1, mb: 1 }}>
                    {group.theme}
                  </Typography>
                  {group.problems.map((p, i) => (
                    <Typography key={i} variant="body2" color="text.secondary">
                      {p}
                    </Typography>
                  ))}
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Section>

      {/* ───────────────────────────────────  HOW ELEVENID SOLVES IT  */}
      <Section bgcolor="grey.50">
        <Typography
          variant="body1"
          color="text.secondary"
          fontStyle="italic"
          textAlign="center"
          sx={{ mb: 3 }}
        >
          Here&apos;s how we fix it.
        </Typography>
        <SectionHeading
          subtitle={t(
            'landingPage.solvesIt.intro',
            'Govern identity with four primitives: trust profiles, credential templates, presentation policies, and flows.'
          )}
          divider
        >
          {t('landingPage.solvesIt.title', `How ${branding.appName} Solves It`)}
        </SectionHeading>

        <Grid container spacing={4}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={4} key={index}>
              <Card
                sx={{
                  height: '100%',
                  textAlign: 'center',
                  transition: 'all 0.2s ease',
                  '&:hover': { transform: 'translateY(-4px)', boxShadow: 6 },
                }}
              >
                <CardContent sx={{ py: 4 }}>
                  {feature.icon}
                  <Typography variant="h6" fontWeight={700} sx={{ mt: 2, mb: 1 }}>
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
      </Section>

      {/* ───────────────────────────────────  HOW IT WORKS (visual flow)  */}
      <Section>
        <SectionHeading
          subtitle={t(
            'landingPage.howItWorks.description',
            'Digital identity is a governed exchange between four actors.'
          )}
          divider
        >
          {t('landingPage.howItWorks.title', 'How It Works')}
        </SectionHeading>

        {/* Horizontal summary flow */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: { xs: 1, md: 2 },
            flexWrap: 'wrap',
            mb: 4,
          }}
        >
          {[
            { label: 'Issuer', color: 'primary.main' },
            null,
            { label: 'Holder', color: 'secondary.main' },
            null,
            { label: 'Verifier', color: 'success.main' },
            null,
            { label: 'Trust Registry', color: 'warning.main', highlight: true },
          ].map((item, i) =>
            item === null ? (
              <ArrowForwardIcon key={`arrow-${i}`} sx={{ color: 'grey.400' }} />
            ) : (
              <Paper
                key={item.label}
                elevation={item.highlight ? 4 : 1}
                sx={{
                  px: { xs: 2, md: 3 },
                  py: 1.5,
                  bgcolor: item.highlight ? 'warning.light' : 'white',
                  border: item.highlight ? '2px solid' : '1px solid',
                  borderColor: item.highlight ? 'warning.main' : 'grey.200',
                  borderRadius: 2,
                  fontWeight: 700,
                  textAlign: 'center',
                  minWidth: { xs: 80, md: 120 },
                }}
              >
                <Typography variant="body2" fontWeight={700} color={item.color}>
                  {item.label}
                </Typography>
              </Paper>
            )
          )}
        </Box>

        <Paper elevation={3} sx={{ p: { xs: 2, md: 4 }, bgcolor: 'grey.50' }}>
          <UnifiedIdentityFlowDiagram interactive={true} />
        </Paper>

        {/* CTA after How It Works */}
        <Box sx={{ textAlign: 'center', mt: 4 }}>
          <Button
            variant="contained"
            size="large"
            component="a"
            href="/identity"
            endIcon={<ArrowForwardIcon />}
            sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
          >
            {t('landingPage.howItWorks.cta', 'Try a live verification flow')}
          </Button>
        </Box>
      </Section>

      {/* ───────────────────────────────────  CHOOSE YOUR PATH  */}
      <Section bgcolor="grey.50">
        <SectionHeading
          subtitle={t('audienceRouting.subtitle', AUDIENCE_ROUTING.subtitle)}
          divider
        >
          {t('audienceRouting.title', AUDIENCE_ROUTING.title)}
        </SectionHeading>
        <Grid container spacing={3} sx={{ maxWidth: 960, mx: 'auto' }}>
          {AUDIENCE_ROUTING.paths.map((path) => (
            <Grid item xs={12} md={4} key={path.id}>
              <Card
                elevation={2}
                sx={{
                  height: '100%',
                  transition: 'all 0.2s ease',
                  '&:hover': { transform: 'translateY(-6px)', boxShadow: 8 },
                }}
              >
                <CardActionArea
                  component="a"
                  href={path.path}
                  sx={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 4, flexGrow: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <Box sx={{ color: `${path.color}.main`, mb: 1 }}>
                      {AUDIENCE_ICONS[path.icon] || <BusinessIcon sx={{ fontSize: 40 }} />}
                    </Box>
                    <Typography variant="h5" fontWeight={700} color={`${path.color}.main`} gutterBottom>
                      {t(`audienceRouting.${path.id}.title`, path.title)}
                    </Typography>
                    <Chip
                      label={path.benefit}
                      size="small"
                      color={path.color}
                      variant="outlined"
                      sx={{ mb: 2, fontWeight: 600 }}
                    />
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 3, flexGrow: 1 }}>
                      {t(`audienceRouting.${path.id}.description`, path.description)}
                    </Typography>
                    <Button
                      variant="outlined"
                      component="span"
                      color={path.color}
                      endIcon={<ArrowForwardIcon />}
                      sx={{ width: { xs: '100%', sm: 'auto' } }}
                    >
                      {t(`audienceRouting.${path.id}.cta`, path.cta)}
                    </Button>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Section>

      {/* ───────────────────────────────────  WHY THIS MATTERS  */}
      <Section>
        <SectionHeading divider>
          {t('organizationOutcomes.title', ORGANIZATION_OUTCOMES.title)}
        </SectionHeading>
        <Grid container spacing={3} sx={{ maxWidth: 900, mx: 'auto' }}>
          {ORGANIZATION_OUTCOMES.outcomes.map((outcome, index) => (
            <Grid item xs={12} sm={6} key={index}>
              <Card
                elevation={2}
                sx={{
                  height: '100%',
                  transition: 'all 0.2s ease',
                  '&:hover': { transform: 'translateY(-3px)', boxShadow: 4 },
                }}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'start', gap: 1.5 }}>
                    <TrendingUpIcon color="success" sx={{ mt: 0.3 }} />
                    <Box>
                      <Typography variant="body1" fontWeight={600}>
                        {typeof outcome === 'string' ? outcome : outcome.text}
                      </Typography>
                      {typeof outcome !== 'string' && outcome.metric && (
                        <Chip
                          label={outcome.metric}
                          size="small"
                          color="success"
                          variant="outlined"
                          sx={{ mt: 1, fontWeight: 600, fontSize: '0.7rem' }}
                        />
                      )}
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Section>

      {/* ───────────────────────────────────  STANDARDS (collapsible layers)  */}
      <Section bgcolor="grey.50">
        <SectionHeading divider>
          {t('landingPage.standards.title', 'Standards-Based Architecture')}
        </SectionHeading>
        <Typography
          variant="h6"
          textAlign="center"
          sx={{
            mb: 4,
            fontWeight: 700,
            color: 'primary.main',
            bgcolor: 'primary.50',
            py: 1.5,
            px: 3,
            borderRadius: 2,
            maxWidth: 520,
            mx: 'auto',
          }}
        >
          {t('landingPage.standards.subtitle', 'Standards are not integrations. They are the product.')}
        </Typography>

        {/* Collapsible layers */}
        <Box sx={{ maxWidth: 800, mx: 'auto', mb: 4 }}>
          {(STANDARDS_INFO?.layers || []).map((layer, idx) => (
            <Paper
              key={idx}
              elevation={expandedLayer === idx ? 3 : 1}
              sx={{ mb: 1, borderRadius: 2, overflow: 'hidden', transition: 'all 0.2s ease' }}
            >
              <Box
                onClick={() => setExpandedLayer(expandedLayer === idx ? null : idx)}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  px: 3,
                  py: 2,
                  cursor: 'pointer',
                  '&:hover': { bgcolor: 'grey.100' },
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                  <Chip label={`Layer ${idx + 1}`} size="small" color="primary" sx={{ fontWeight: 700, fontSize: '0.7rem' }} />
                  <Typography variant="subtitle1" fontWeight={700}>{layer.name}</Typography>
                </Box>
                {expandedLayer === idx ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </Box>
              <Collapse in={expandedLayer === idx}>
                <Box sx={{ px: 3, pb: 2 }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                    {layer.description}
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {layer.standards?.map((std) => (
                      <Chip
                        key={std.name}
                        label={`${std.name} — ${std.description}`}
                        variant="outlined"
                        size="small"
                      />
                    ))}
                  </Box>
                </Box>
              </Collapse>
            </Paper>
          ))}
        </Box>

        <Paper elevation={3} sx={{ p: { xs: 2, md: 4 }, bgcolor: 'white' }}>
          <StandardsStackDiagram interactive={false} />
        </Paper>

        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mt: 3, maxWidth: 700, mx: 'auto' }}>
          {t(
            'landingPage.standards.description',
            "These layers let ElevenID LLC interoperate across governments, wallets, and enterprises without custom integrations."
          )}
        </Typography>
        <Box sx={{ textAlign: 'center', mt: 2 }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/standards"
            endIcon={<ArrowForwardIcon />}
            sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
          >
            {t('landingPage.standards.cta', 'Explore Standards')}
          </Button>
        </Box>
      </Section>

      {/* ───────────────────────────────────  PRODUCTS (cleaned up)  */}
      <Section>
        <SectionHeading
          subtitle={t('landingPage.products.description', 'A complete platform—from issuance to verification and governance.')}
          divider
        >
          {t('landingPage.products.title', 'Products & Capabilities')}
        </SectionHeading>

        <Grid container spacing={3}>
          {PRODUCTS.slice(0, 4).map((product) => (
            <Grid item xs={12} sm={6} md={3} key={product.id}>
              <Card
                elevation={2}
                sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  transition: 'all 0.2s ease',
                  '&:hover': { transform: 'translateY(-4px)', boxShadow: 6 },
                }}
              >
                <CardContent sx={{ flexGrow: 1, textAlign: 'center' }}>
                  <Box sx={{ mb: 1 }}>{PRODUCT_ICONS[product.id]}</Box>
                  <Typography variant="h6" fontWeight={700} gutterBottom>
                    {product.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {product.tagline}
                  </Typography>
                  <Box sx={{ mt: 1 }}>
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
                <Box sx={{ p: 2, pt: 0, textAlign: 'center' }}>
                  <Button
                    size="small"
                    fullWidth
                    variant="text"
                    component="a"
                    href="/product"
                    endIcon={<ArrowForwardIcon fontSize="small" />}
                    sx={{ '&:hover': { bgcolor: 'primary.50' } }}
                  >
                    {t('landingPage.products.viewDetails', 'View Details')}
                  </Button>
                </Box>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ textAlign: 'center', mt: 4 }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/product"
            endIcon={<ArrowForwardIcon />}
            sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
          >
            {t('landingPage.products.viewAll', 'View All Products')}
          </Button>
        </Box>
      </Section>

      {/* ───────────────────────────────────  TRUST SIGNALS (enterprise-grade)  */}
      <Section bgcolor="grey.50">
        <SectionHeading divider>
          {t('landingPage.trustSignals.title', 'Enterprise-Grade Infrastructure')}
        </SectionHeading>

        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card elevation={2} sx={{ height: '100%', transition: 'all 0.2s ease', '&:hover': { boxShadow: 4 } }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700} color="primary" gutterBottom>
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
            <Card elevation={2} sx={{ height: '100%', transition: 'all 0.2s ease', '&:hover': { boxShadow: 4 } }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700} color="secondary" gutterBottom>
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
            <Card elevation={2} sx={{ height: '100%', transition: 'all 0.2s ease', '&:hover': { boxShadow: 4 } }}>
              <CardContent>
                <Typography variant="h6" fontWeight={700} color="success.main" gutterBottom>
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
      </Section>

      {/* ─── Proof & Credibility Strip ─── */}
      <Paper 
        elevation={0} 
        sx={{ 
          py: 3, 
          px: 3, 
          bgcolor: 'grey.50', 
          borderRadius: 0,
          border: '1px solid',
          borderColor: 'grey.200'
        }}
      >
        <Typography variant="subtitle1" fontWeight={700} textAlign="center" sx={{ mb: 2 }}>
          {t('proofStrip.title', PROOF_STRIP.title)}
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 1.5 }}>
          {proofClaims.map((claim) => (
            <Chip
              key={`${claim.category}:${claim.label}`}
              label={`${claim.category}: ${claim.label}`}
              variant="outlined"
              sx={{ borderColor: 'grey.400', '&:hover': { borderColor: 'primary.main', bgcolor: 'primary.50' }, transition: 'all 0.2s ease' }}
            />
          ))}
        </Box>
      </Paper>

      {/* ───────────────────────────────────  OPEN STANDARD (MIP)  */}
      <Section>
        <SectionHeading
          subtitle={t('protocol.heroSubtitle', PROTOCOL.tagline)}
          divider
        >
          {t('protocol.heroTitle', 'Built on an Open Standard')}
        </SectionHeading>

        <Paper
          elevation={0}
          sx={{
            p: 4,
            mb: 4,
            bgcolor: 'grey.50',
            borderRadius: 2,
            textAlign: 'center',
            border: '1px solid',
            borderColor: 'grey.200',
          }}
        >
          <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1, mb: 2 }}>
            <Chip label="Open Standard" color="primary" size="small" sx={{ fontWeight: 700 }} />
            <Chip label={`v${PROTOCOL.version}`} variant="outlined" size="small" />
            <Chip label={PROTOCOL.license} variant="outlined" size="small" />
          </Box>
          <Typography variant="h6" fontWeight={600} color="primary.dark" sx={{ fontStyle: 'italic', maxWidth: 800, mx: 'auto', mb: 2 }}>
            &ldquo;{PROTOCOL.thesis}&rdquo;
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 700, mx: 'auto' }}>
            The Marty Identity Protocol (MIP) defines five primitives—Trust Profiles, Credential Templates,
            Presentation Policies, Deployment Profiles, and Flows—that make digital identity management
            fully automatable and vendor-neutral.
          </Typography>
        </Paper>

        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<GitHubIcon />}
            href={PROTOCOL.githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
          >
            View Protocol on GitHub
          </Button>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/protocol"
            endIcon={<ArrowForwardIcon />}
            sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
          >
            Learn About MIP
          </Button>
        </Box>
      </Section>

      {/* ─────────────────────────  LEARN THE PROTOCOL  */}
      <Section bgcolor="grey.50">
        <Box textAlign="center" sx={{ mb: 5 }}>
          <Typography variant="h3" fontWeight={800} gutterBottom>
            Learn the Marty Protocol
          </Typography>
          <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 620, mx: 'auto' }}>
            Six structured chapters — from the foundations of verifiable identity to concrete implementations.
          </Typography>
        </Box>

        {/* Chapter intro links */}
        <Grid container spacing={2} sx={{ maxWidth: 960, mx: 'auto', mb: 4 }} justifyContent="center">
          {GUIDE_CHAPTERS.map((ch) => {
            const firstArticle = (GUIDE_ARTICLES_BY_CHAPTER[ch.id] || [])[0];
            return (
              <Grid item xs={6} sm={4} md={2} key={ch.id}>
                <Card
                  component="a"
                  href={firstArticle ? `/blog/${firstArticle.slug}` : '/blog'}
                  elevation={0}
                  sx={{
                    display: 'block',
                    textAlign: 'center',
                    p: 2,
                    textDecoration: 'none',
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 2,
                    bgcolor: 'background.paper',
                    transition: 'all 0.18s ease',
                    '&:hover': { borderColor: 'primary.main', transform: 'translateY(-2px)', boxShadow: 3 },
                  }}
                >
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ display: 'block', mb: 0.5 }}
                  >
                    Chapter {ch.id}
                  </Typography>
                  <Typography variant="body2" fontWeight={700} color="text.primary">
                    {ch.title}
                  </Typography>
                </Card>
              </Grid>
            );
          })}
        </Grid>

        {/* Compact protocol map */}
        <Box sx={{ maxWidth: 900, mx: 'auto', my: 4 }}>
          <InteractiveProtocolMap compact />
        </Box>

        <Box textAlign="center">
          <Button
            variant="contained"
            size="large"
            component="a"
            href="/blog/foundations-identity"
            endIcon={<ArrowForwardIcon />}
          >
            Start with Foundations
          </Button>
          <Button
            variant="text"
            size="large"
            component="a"
            href="/blog"
            sx={{ ml: 2 }}
          >
            Browse All Guides
          </Button>
        </Box>
      </Section>

      {/* ─────────────────────────────  INSIGHTS & ARTICLES  */}
      <Section>
        <Box textAlign="center" sx={{ mb: 6 }}>
          <Typography variant="h3" fontWeight={800} gutterBottom>
            Insights &amp; Articles
          </Typography>
          <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600, mx: 'auto' }}>
            Technical insights, implementation guides, and business perspectives from the Marty team.
          </Typography>
        </Box>
        <Grid container spacing={3}>
          {[...BLOG_POSTS]
            .filter((p) => p.date <= new Date().toISOString().slice(0, 10))
            .sort((a, b) => new Date(b.date) - new Date(a.date))
            .slice(0, 3)
            .map((post) => (
              <Grid item xs={12} md={4} key={post.slug}>
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    transition: 'all 0.2s ease',
                    '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 },
                  }}
                >
                  <CardActionArea
                    component="a"
                    href={`/blog/${post.slug}`}
                    sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}
                  >
                    <CardContent sx={{ flexGrow: 1, width: '100%' }}>
                      <Chip
                        label={post.category}
                        size="small"
                        color="primary"
                        variant="outlined"
                        sx={{ mb: 1.5, fontWeight: 600 }}
                      />
                      <Typography variant="h6" fontWeight={700} gutterBottom>
                        {post.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {post.summary}
                      </Typography>
                      <Typography variant="caption" color="text.disabled">
                        {new Date(post.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} · {post.readTime}
                      </Typography>
                    </CardContent>
                  </CardActionArea>
                </Card>
              </Grid>
            ))}
        </Grid>
        <Box textAlign="center" sx={{ mt: 5 }}>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/blog"
            endIcon={<ArrowForwardIcon />}
          >
            View All Articles
          </Button>
        </Box>
      </Section>

      {/* ───────────────────────────────────  FOOTER CTA  */}
      <Box 
        sx={{ 
          textAlign: 'center', 
          py: { xs: 6, md: 8 }, 
          px: 2,
          background: 'linear-gradient(135deg, #1976d2 0%, #0d47a1 100%)',
          color: 'white',
          borderRadius: 2,
          mt: 0,
        }}
      >
        <Typography variant="h4" gutterBottom fontWeight={800}>
          {t('landingPage.footer.title', 'Ready to get started?')}
        </Typography>
        <Typography variant="body1" sx={{ mb: 4, maxWidth: 600, mx: 'auto', opacity: 0.9 }}>
          {t('landingPage.footer.description', 'Start free, or compare plans for your organization.')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<VerifiedUserIcon />}
            onClick={() => register()}
            sx={{
              bgcolor: 'white',
              color: 'primary.main',
              fontWeight: 700,
              px: 4,
              '&:hover': { bgcolor: 'grey.100', transform: 'translateY(-2px)', boxShadow: 4 },
              width: { xs: '100%', sm: 'auto' },
              transition: 'all 0.2s ease',
            }}
          >
            {t('valueProposition.primaryCTA', VALUE_PROPOSITION.primaryCTA)}
          </Button>
          <Button
            variant="outlined"
            size="large"
            component="a"
            href="/pricing"
            sx={{
              borderColor: 'white',
              color: 'white',
              px: 4,
              '&:hover': { bgcolor: 'rgba(255,255,255,0.12)', borderColor: 'white', transform: 'translateY(-2px)' },
              width: { xs: '100%', sm: 'auto' },
              transition: 'all 0.2s ease',
            }}
          >
            {t('landingPage.footer.viewPricing', 'View Pricing')}
          </Button>
        </Box>
      </Box>

      {/* Orientation Banner */}
      <Box 
        sx={{ 
          mt: 4, 
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
