/**
 * Landing Page Component
 *
 * Public landing page shown to unauthenticated users.
 * Provides information about the service, pricing tiers, and prompts login.
 */

import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardActions,
  Grid,
  Container,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  Snackbar
} from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import SecurityIcon from '@mui/icons-material/Security';
import CheckIcon from '@mui/icons-material/Check';
import CloseIcon from '@mui/icons-material/Close';
import StarIcon from '@mui/icons-material/Star';
import BusinessIcon from '@mui/icons-material/Business';
import StorefrontIcon from '@mui/icons-material/Storefront';
import PersonIcon from '@mui/icons-material/Person';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';

/**
 * Pricing tier configuration
 * Matches PLAN_LIMITS in PaymentContext
 */
const PRICING_TIERS = [
  {
    name: 'FREE',
    price: 0,
    description: 'Perfect for getting started',
    features: [
      { text: 'Up to 5 team members', included: true },
      { text: '100 API calls/month', included: true },
      { text: '10 credentials/month', included: true },
      { text: 'Email support', included: true },
      { text: 'Custom branding', included: false },
      { text: 'Priority support', included: false },
      { text: 'Webhooks', included: false },
    ],
    buttonText: 'Start Free',
    highlighted: false,
  },
  {
    name: 'STARTER',
    price: 49,
    description: 'For small teams',
    features: [
      { text: 'Up to 25 team members', included: true },
      { text: '1,000 API calls/month', included: true },
      { text: '100 credentials/month', included: true },
      { text: 'Email support', included: true },
      { text: 'Custom branding', included: false },
      { text: 'Priority support', included: false },
      { text: 'Webhooks', included: true },
    ],
    buttonText: 'Get Started',
    highlighted: false,
  },
  {
    name: 'PROFESSIONAL',
    price: 199,
    description: 'For growing businesses',
    features: [
      { text: 'Up to 100 team members', included: true },
      { text: '10,000 API calls/month', included: true },
      { text: '1,000 credentials/month', included: true },
      { text: 'Priority email support', included: true },
      { text: 'Custom branding', included: true },
      { text: 'Priority support', included: true },
      { text: 'Webhooks', included: true },
    ],
    buttonText: 'Go Professional',
    highlighted: true,
  },
  {
    name: 'ENTERPRISE',
    price: null, // Custom pricing
    description: 'For large organizations',
    features: [
      { text: 'Unlimited team members', included: true },
      { text: 'Unlimited API calls', included: true },
      { text: 'Unlimited credentials', included: true },
      { text: 'Dedicated support', included: true },
      { text: 'Custom branding', included: true },
      { text: 'Priority support', included: true },
      { text: 'Webhooks + Custom integrations', included: true },
    ],
    buttonText: 'Contact Sales',
    highlighted: false,
  },
];

function LandingPage() {
  const branding = useBranding();
  const { isAuthenticated, isLoading, login, register, isAdministrator, isVendor } = useAuth();
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

  // Show nothing while checking auth to avoid flash
  if (isLoading || (isAuthenticated && checkingOnboarding)) {
    return null;
  }

  const features = [
    {
      icon: <FlightTakeoffIcon sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Travel Documents',
      description: 'Apply for and manage your travel documents securely.',
    },
    {
      icon: <VerifiedUserIcon sx={{ fontSize: 48, color: 'success.main' }} />,
      title: 'Verified Credentials',
      description: 'Digitally verifiable credentials following international standards.',
    },
    {
      icon: <SecurityIcon sx={{ fontSize: 48, color: 'warning.main' }} />,
      title: 'Secure & Trusted',
      description: 'Built on ICAO PKD infrastructure with enterprise-grade security.',
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
          {branding.appName}
        </Typography>
        <Typography variant="h6" sx={{ mb: 4, opacity: 0.9 }}>
          {branding.tagline}
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<LoginIcon />}
          onClick={() => login()}
          sx={{
            bgcolor: 'white',
            color: 'primary.main',
            '&:hover': { bgcolor: 'grey.100' },
            px: 4,
            py: 1.5,
            mr: 2,
          }}
        >
          Sign In to Continue
        </Button>
        <Button
          variant="outlined"
          size="large"
          onClick={() => register()}
          data-testid="get-started-btn"
          sx={{
            borderColor: 'white',
            color: 'white',
            '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', borderColor: 'white' },
            px: 4,
            py: 1.5,
          }}
        >
          Get Started
        </Button>
      </Box>

      {/* Features Grid */}
      <Grid container spacing={4} sx={{ mb: 4 }}>
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

      {/* User Type Info */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <PersonIcon color="info" />
                <Typography variant="h6" color="info.main">
                  For Applicants
                </Typography>
              </Box>
              <Typography variant="body2" color="textSecondary">
                Browse available credentials, submit applications, track your status, and 
                access your issued documents securely.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <StorefrontIcon color="secondary" />
                <Typography variant="h6" color="secondary">
                  For Vendors
                </Typography>
              </Box>
              <Typography variant="body2" color="textSecondary">
                Manage your organization, configure API keys, invite applicants, and set 
                processing fees for credential issuance.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <BusinessIcon color="primary" />
                <Typography variant="h6" color="primary">
                  For Administrators
                </Typography>
              </Box>
              <Typography variant="body2" color="textSecondary">
                Manage applicant vetting, issue travel documents, configure trust policies, 
                and monitor system operations.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Pricing Section */}
      <Box sx={{ mt: 8, mb: 4, textAlign: 'center' }}>
        <Typography variant="h4" component="h2" gutterBottom fontWeight="bold">
          Pricing Plans
        </Typography>
        <Typography variant="body1" color="textSecondary" sx={{ mb: 4 }}>
          Choose the plan that fits your organization's needs
        </Typography>
      </Box>

      <Grid container spacing={3} sx={{ mb: 6 }}>
        {PRICING_TIERS.map((tier) => (
          <Grid item xs={12} sm={6} md={3} key={tier.name}>
            <Card 
              sx={{ 
                height: '100%', 
                display: 'flex', 
                flexDirection: 'column',
                border: tier.highlighted ? 2 : 1,
                borderColor: tier.highlighted ? 'primary.main' : 'divider',
                position: 'relative'
              }}
            >
              {tier.highlighted && (
                <Chip
                  icon={<StarIcon />}
                  label="Most Popular"
                  color="primary"
                  size="small"
                  sx={{
                    position: 'absolute',
                    top: -12,
                    left: '50%',
                    transform: 'translateX(-50%)'
                  }}
                />
              )}
              <CardHeader
                title={tier.name}
                subheader={tier.description}
                titleTypographyProps={{ align: 'center', fontWeight: 'bold' }}
                subheaderTypographyProps={{ align: 'center' }}
                sx={{ pb: 0 }}
              />
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ textAlign: 'center', mb: 2 }}>
                  {tier.price !== null ? (
                    <>
                      <Typography variant="h3" component="span" fontWeight="bold">
                        ${tier.price}
                      </Typography>
                      <Typography variant="subtitle1" color="textSecondary">
                        /month
                      </Typography>
                    </>
                  ) : (
                    <Typography variant="h5" fontWeight="bold" color="textSecondary">
                      Custom Pricing
                    </Typography>
                  )}
                </Box>
                <Divider sx={{ my: 2 }} />
                <List dense>
                  {tier.features.map((feature, index) => (
                    <ListItem key={index} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {feature.included ? (
                          <CheckIcon fontSize="small" color="success" />
                        ) : (
                          <CloseIcon fontSize="small" color="disabled" />
                        )}
                      </ListItemIcon>
                      <ListItemText 
                        primary={feature.text}
                        primaryTypographyProps={{
                          variant: 'body2',
                          color: feature.included ? 'textPrimary' : 'textSecondary'
                        }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
              <CardActions sx={{ p: 2, pt: 0 }}>
                <Button
                  fullWidth
                  variant={tier.highlighted ? 'contained' : 'outlined'}
                  color="primary"
                  onClick={() => login()}
                >
                  {tier.buttonText}
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Footer CTA */}
      <Box 
        sx={{ 
          textAlign: 'center', 
          py: 4, 
          bgcolor: 'grey.100', 
          borderRadius: 2,
          mb: 2
        }}
      >
        <Typography variant="h5" gutterBottom>
          Ready to get started?
        </Typography>
        <Typography variant="body1" color="textSecondary" sx={{ mb: 2 }}>
          Sign up today and start issuing secure digital credentials
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<LoginIcon />}
          onClick={() => register()}
          sx={{ px: 4 }}
        >
          Create Your Account
        </Button>
      </Box>
    </Box>
  );
}

export default LandingPage;
