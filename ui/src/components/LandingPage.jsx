/**
 * Landing Page Component
 *
 * Public landing page shown to unauthenticated users.
 * Provides information about the service, pricing tiers, and prompts login.
 */

import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
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
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';
import { 
  VALUE_PROPOSITION, 
  IDENTITY_CONCEPTS, 
  PRODUCTS, 
  TRUST_SIGNALS,
  IDV_COMPARISON,
  EUDI_OPEN_BADGES,
  ORGANIZATION_OUTCOMES,
  AUDIENCE_ROUTING,
  PROOF_STRIP,
} from '../data/marketingContent';
import { UnifiedIdentityFlowDiagram, StandardsStackDiagram } from './diagrams';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

function LandingPage() {
  const brandingContext = useBranding();
  const branding = brandingContext?.branding || { appName: 'ElevenID' };
  const { isAuthenticated, isLoading, register, isAdministrator, isVendor } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [authError, setAuthError] = useState(null);
  const [checkingOnboarding, setCheckingOnboarding] = useState(false);

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

  // Redirect authenticated users to appropriate dashboard
  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      const checkOnboarding = async () => {
        setCheckingOnboarding(true);
        try {
          const response = await fetch(`${API_BASE_URL}/api/onboarding/status`, {
            credentials: 'include',
          });

          if (response.ok) {
            const data = await response.json();
            if (data.needs_onboarding) {
              navigate('/onboarding', { replace: true });
              return;
            }

            if (data.user_type === 'administrator' || isAdministrator) {
              navigate('/dashboard', { replace: true });
            } else if (data.user_type === 'vendor' || isVendor) {
              navigate('/vendor', { replace: true });
            } else {
              navigate('/credentials', { replace: true });
            }
            return;
          }

          if (response.status === 401) {
            setCheckingOnboarding(false);
            return;
          }
        } catch (error) {
          console.error('Error checking onboarding status:', error);
        } finally {
          setCheckingOnboarding(false);
        }

        if (isAdministrator) {
          navigate('/dashboard', { replace: true });
        } else if (isVendor) {
          navigate('/vendor', { replace: true });
        } else {
          navigate('/credentials', { replace: true });
        }
      };

      checkOnboarding();
    }
  }, [isAuthenticated, isLoading, isAdministrator, isVendor, navigate]);

  const handleCloseError = () => {
    setAuthError(null);
  };

  // Show loading spinner while checking auth instead of blank page
  if (isLoading) {
    return (
      <Box 
        display="flex" 
        justifyContent="center" 
        alignItems="center" 
        minHeight="50vh"
        flexDirection="column"
        gap={2}
      >
        <CircularProgress />
        <Typography color="text.secondary">Loading...</Typography>
      </Box>
    );
  }

  // If authenticated and checking onboarding, show a different message
  if (isAuthenticated && checkingOnboarding) {
    return (
      <Box 
        display="flex" 
        justifyContent="center" 
        alignItems="center" 
        minHeight="50vh"
        flexDirection="column"
        gap={2}
      >
        <CircularProgress />
        <Typography color="text.secondary">Checking your account...</Typography>
      </Box>
    );
  }

  const features = [
    {
      icon: <FlightTakeoffIcon sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Issuance',
      description: 'Issue standards-based credentials with cryptographic signatures and policy enforcement.',
    },
    {
      icon: <VerifiedUserIcon sx={{ fontSize: 48, color: 'success.main' }} />,
      title: 'Verification',
      description: 'Verify credentials against trust anchors with revocation checking and selective disclosure.',
    },
    {
      icon: <SecurityIcon sx={{ fontSize: 48, color: 'warning.main' }} />,
      title: 'Governance',
      description: 'Manage trust, policy, and deployment centrally—without changing verifier code.',
    },
  ];

  return (
    <Box>
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
          {VALUE_PROPOSITION.headline}
        </Typography>
        <Typography variant="h4" sx={{ mb: 2, opacity: 0.95, maxWidth: 900, mx: 'auto' }}>
          {VALUE_PROPOSITION.subheadline}
        </Typography>
        <Typography variant="h6" sx={{ mb: 4, opacity: 0.85, maxWidth: 800, mx: 'auto' }}>
          {VALUE_PROPOSITION.extendedSubheadline}
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
            Start Free
          </Button>
          <Button
            variant="outlined"
            size="large"
            endIcon={<ArrowForwardIcon />}
            onClick={() => navigate(VALUE_PROPOSITION.secondaryCTA.path)}
            sx={{
              borderColor: 'white',
              color: 'white',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', borderColor: 'white' },
              px: 4,
              py: 1.5,
            }}
          >
            {VALUE_PROPOSITION.secondaryCTA.label} →
          </Button>
        </Box>
      </Box>

      {/* IDV Comparison Section */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {IDV_COMPARISON.title}
        </Typography>
        <Grid container spacing={3} sx={{ mt: 2 }}>
          <Grid item xs={12} md={6}>
            <Paper elevation={2} sx={{ p: 3, height: '100%', bgcolor: 'grey.100' }}>
              <Typography variant="h6" fontWeight="bold" gutterBottom color="text.secondary">
                Traditional IDV Platforms
              </Typography>
              <List>
                {IDV_COMPARISON.traditional.map((item, index) => (
                  <ListItem key={index} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon fontSize="small" color="action" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={item.label}
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
                {IDV_COMPARISON.elevenid.map((item, index) => (
                  <ListItem key={index} sx={{ py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon fontSize="small" sx={{ color: 'success.light' }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={item.label}
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
          {IDV_COMPARISON.takeaway}
        </Typography>
      </Box>

      {/* EUDI & Open Badges Section */}
      <Paper elevation={3} sx={{ p: 4, mb: 8, bgcolor: 'success.light', borderRadius: 2 }}>
        <Typography variant="h5" gutterBottom fontWeight="bold" color="success.dark">
          {EUDI_OPEN_BADGES.title}
        </Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {EUDI_OPEN_BADGES.points.map((point, index) => (
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
            &ldquo;{EUDI_OPEN_BADGES.quote}&rdquo;
          </Typography>
        </Paper>
      </Paper>

      {/* Audience Routing Block */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {AUDIENCE_ROUTING.title}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4 }}>
          {AUDIENCE_ROUTING.subtitle}
        </Typography>
        <Grid container spacing={3}>
          {AUDIENCE_ROUTING.paths.map((path) => (
            <Grid item xs={12} md={4} key={path.id}>
              <Card 
                elevation={2} 
                sx={{ 
                  height: '100%', 
                  cursor: 'pointer',
                  transition: 'transform 0.2s, box-shadow 0.2s',
                  '&:hover': { 
                    transform: 'translateY(-4px)', 
                    boxShadow: 4 
                  },
                }}
                onClick={() => navigate(path.path)}
              >
                <CardContent sx={{ textAlign: 'center', py: 4 }}>
                  <Typography variant="h5" fontWeight="bold" color={`${path.color}.main`} gutterBottom>
                    {path.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3, minHeight: 60 }}>
                    {path.description}
                  </Typography>
                  <Button
                    variant="outlined"
                    color={path.color}
                    endIcon={<ArrowForwardIcon />}
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(path.path);
                    }}
                  >
                    {path.cta}
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
          The Identity Problem
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 700, mx: 'auto' }}>
          Most organizations face fragmented systems, unclear trust, and growing compliance pressure.
        </Typography>

        <Grid container spacing={3}>
          {IDENTITY_CONCEPTS.whatIs.problems.map((problem, index) => (
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

      {/* How ElevenID Solves It */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          How {branding.appName} Solves It
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 2, maxWidth: 800, mx: 'auto' }}>
          Govern identity with four primitives: trust profiles, credential templates, presentation policies, and flows.
        </Typography>
        <Typography variant="body2" color="primary.main" textAlign="center" paragraph sx={{ mb: 4, fontWeight: 500 }}>
          Policies are configuration, not code. Endpoints execute centrally governed trust and disclosure rules without redeployment.
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
          How It Works
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          Digital identity is a governed exchange between four actors.
        </Typography>

        <Paper elevation={3} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <UnifiedIdentityFlowDiagram interactive={true} />
        </Paper>

        <Box sx={{ textAlign: 'center', mt: 3 }}>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/identity')}
            endIcon={<ArrowForwardIcon />}
          >
            See the Full Flow →
          </Button>
        </Box>
      </Box>

      {/* Why This Matters for Organizations */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {ORGANIZATION_OUTCOMES.title}
        </Typography>
        <Grid container spacing={3} sx={{ mt: 2 }}>
          {ORGANIZATION_OUTCOMES.outcomes.map((outcome, index) => (
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
          Standards-Based Architecture
        </Typography>
        <Typography 
          variant="h6" 
          textAlign="center" 
          sx={{ mb: 4, fontWeight: 500, color: 'primary.main' }}
        >
          Standards are not integrations. They are the product.
        </Typography>

        <Paper elevation={3} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <StandardsStackDiagram interactive={false} />
        </Paper>

        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mt: 3, mb: 2, maxWidth: 700, mx: 'auto' }}>
          These layers let ElevenID interoperate across governments, wallets, and enterprises without custom integrations.
        </Typography>

        <Box sx={{ textAlign: 'center' }}>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/standards')}
            endIcon={<ArrowForwardIcon />}
          >
            Explore Standards
          </Button>
        </Box>
      </Box>

      {/* What to buy first? - Product on-ramp */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          What are you doing first?
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 600, mx: 'auto' }}>
          Choose a starting point. You can expand into a full ecosystem when you&apos;re ready.
        </Typography>
        <Grid container spacing={2} justifyContent="center">
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/product#verification-api"
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
                  Verify credentials
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Verify EUDI wallets, Open Badges, and ISO credentials.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/product#issuance-api"
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
                  Issue credentials
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Issue workforce, education, or government credentials.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/product#kiosk"
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
                  Offline / facility
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Verify at checkpoints with limited connectivity.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card 
              component="a"
              href="/product#authenticator"
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
                  Wallet experience
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Give users a wallet to hold and present credentials.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mt: 2 }}>
          Not sure?{' '}
          <Typography 
            component="a" 
            href="/product#verification-api"
            sx={{ color: 'primary.main', cursor: 'pointer', textDecoration: 'underline' }}
          >
            Start with Verification API →
          </Typography>
        </Typography>
      </Box>

      {/* Products & Capabilities */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          Products & Capabilities
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          A complete platform—from issuance to verification and governance.
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
                    endIcon={<ArrowForwardIcon fontSize="small" />}
                    onClick={() => navigate('/product')}
                    sx={{ justifyContent: 'flex-start' }}
                  >
                    View Details
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
            onClick={() => navigate('/product')}
            endIcon={<ArrowForwardIcon />}
          >
            View All Products
          </Button>
        </Box>
      </Box>

      {/* Trust Signals */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          Enterprise-Grade Infrastructure
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card elevation={2}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
                  Security
                </Typography>
                <List dense>
                  {TRUST_SIGNALS.security.map((item) => (
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
                  Infrastructure
                </Typography>
                <List dense>
                  {TRUST_SIGNALS.infrastructure.map((item) => (
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
                  Compliance
                </Typography>
                <List dense>
                  {TRUST_SIGNALS.compliance.map((item) => (
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
          {PROOF_STRIP.title}
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 2 }}>
          {PROOF_STRIP.claims.map((claim) => (
            <Chip
              key={claim.label}
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
          <strong>Built-in portals</strong> for applicants, vendors, and admins—manage API keys, trust policies, and operations in one place.{' '}
          <Typography
            component="span"
            onClick={() => navigate('/product')}
            sx={{
              color: 'primary.main',
              textDecoration: 'underline',
              cursor: 'pointer',
              '&:hover': { color: 'primary.dark' }
            }}
          >
            Learn more →
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
          Ready to get started?
        </Typography>
        <Typography variant="body1" color="textSecondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
          Start free, or compare plans for your organization.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<LoginIcon />}
            onClick={() => register()}
            sx={{ px: 4 }}
          >
            Start Free
          </Button>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/pricing')}
            sx={{ px: 4 }}
          >
            View Pricing
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
          <strong>New to verifiable identity?</strong>
        </Typography>
        <Button
          size="small"
          onClick={() => navigate('/identity')}
          endIcon={<ArrowForwardIcon fontSize="small" />}
          sx={{ textTransform: 'none' }}
        >
          How It Works
        </Button>
      </Box>
    </Box>
  );
}

export default LandingPage;
