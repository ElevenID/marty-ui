/**
 * Product Page
 * 
 * Comprehensive overview of ElevenID LLC products with capabilities,
 * deployment options, standards, and use cases
 */

import { Box, Typography, Button, Card, CardContent, CardHeader, Grid, Chip, Divider, List, ListItem, ListItemIcon, ListItemText, Paper } from '@mui/material';
import { SEOHead } from './seo';
import { softwareApplicationSchema, breadcrumbListSchema } from './seo/structuredData';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CloudIcon from '@mui/icons-material/Cloud';
import StorageIcon from '@mui/icons-material/Storage';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import ComputerIcon from '@mui/icons-material/Computer';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import SecurityIcon from '@mui/icons-material/Security';
import AccountBalanceWalletIcon from '@mui/icons-material/AccountBalanceWallet';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import GitHubIcon from '@mui/icons-material/GitHub';
import { useNavigate } from 'react-router-dom';
import { DISABLE_PUBLIC_PRICING_BUTTONS, SHOW_PUBLIC_PRICING_BUTTONS } from '@ui-public-config';
import FutureFeatureButton from './FutureFeatureButton';
import { PRODUCTS } from '../data/marketingContent';
import { useBranding } from '../hooks/useBranding';

const DEPLOYMENT_ICONS = {
  'SaaS': <CloudIcon />,
  'Self-hosted': <StorageIcon />,
  'On-site application': <ComputerIcon />,
  'Mobile (iOS, Android)': <PhoneAndroidIcon />,
  'Desktop': <ComputerIcon />,
};

function ProductPage() {
  const navigate = useNavigate();
  const branding = useBranding();

  return (
    <Box>
      {/* SEO Meta Tags */}
      <SEOHead
        title="Verifiable Credential APIs"
        description="Enterprise verifiable credential infrastructure: Verification API, Issuance API, Kiosk, and Authenticator. EUDI, Open Badges, ISO 18013-5, SD-JWT support."
        canonicalPath="/product"
        keywords={['verifiable credential API', 'EUDI Wallet API', 'Open Badges API', 'ISO 18013-5', 'credential issuance', 'credential verification']}
        structuredData={[
          softwareApplicationSchema({
            name: 'ElevenID LLC Verifiable Credential Platform',
            description: 'Enterprise verifiable credential infrastructure for issuing, verifying, and governing digital credentials.',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'Products', url: 'https://elevenidllc.com/product' },
          ]),
        ]}
      />
      
      {/* Hero Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          mb: 6,
          background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          Verifiable Credential Products & APIs
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          Choose the building blocks you need—start with verification, then expand into issuance and governance.
        </Typography>
      </Box>

      {/* Product Overview */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="body1" color="text.secondary" paragraph sx={{ maxWidth: 900, mx: 'auto', textAlign: 'center' }}>
          {branding.branding.appName} is a complete identity infrastructure platform for issuing, verifying, 
          and governing digital credentials—built on open standards for interoperability and trust.
        </Typography>
      </Box>

      {/* Start Here Router */}
      <Paper elevation={2} sx={{ p: 4, mb: 6, bgcolor: 'grey.50', borderRadius: 2 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom textAlign="center">
          What are you doing first?
        </Typography>
        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mb: 3 }}>
          Most teams start with Verification API.
        </Typography>
        <Grid container spacing={2} justifyContent="center">
          <Grid item xs={6} sm={3}>
            <Card 
              elevation={1} 
              component="a"
              href="/verifiable-credential-api"
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <VerifiedUserIcon sx={{ fontSize: 32, color: 'primary.main', mb: 1 }} />
                <Typography variant="subtitle2" fontWeight="bold">
                  Verify
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card 
              elevation={1}
              component="a"
              href="/open-badges-issuance"
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <FlightTakeoffIcon sx={{ fontSize: 32, color: 'secondary.main', mb: 1 }} />
                <Typography variant="subtitle2" fontWeight="bold">
                  Issue
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card 
              elevation={1}
              component="a"
              href="/iso-18013-5-mdoc-verification"
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <SecurityIcon sx={{ fontSize: 32, color: 'warning.main', mb: 1 }} />
                <Typography variant="subtitle2" fontWeight="bold">
                  Offline
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Card 
              elevation={1}
              component="a"
              href="/eudi-wallet-verification"
              sx={{ 
                height: '100%', 
                cursor: 'pointer',
                textDecoration: 'none',
                display: 'block',
                transition: 'all 0.2s',
                '&:hover': { transform: 'translateY(-4px)', boxShadow: 4 }
              }}
            >
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <AccountBalanceWalletIcon sx={{ fontSize: 32, color: 'info.main', mb: 1 }} />
                <Typography variant="subtitle2" fontWeight="bold">
                  Wallet
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* Recommended Packages */}
      <Box sx={{ mb: 6 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom>
          Recommended Packages
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card elevation={2} sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
                  Verifier Starter
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Verification API (SaaS)" primaryTypographyProps={{ variant: 'body2' }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Trust registry integration" primaryTypographyProps={{ variant: 'body2' }} />
                  </ListItem>
                </List>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Best for: Relying parties, acceptance scenarios
                </Typography>
                <Typography variant="body2" fontWeight="medium" color="success.dark" sx={{ mt: 1 }}>
                  Outcome: Accept wallets and credentials without repeated KYC.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card elevation={2} sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="secondary" gutterBottom>
                  Issuer Starter
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Issuance API (self-hosted)" primaryTypographyProps={{ variant: 'body2' }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Verification API for testing" primaryTypographyProps={{ variant: 'body2' }} />
                  </ListItem>
                </List>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Best for: Credential issuers, program operators
                </Typography>
                <Typography variant="body2" fontWeight="medium" color="success.dark" sx={{ mt: 1 }}>
                  Outcome: Issue compliant credentials with full control of keys and lifecycle.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card elevation={2} sx={{ height: '100%', border: 2, borderColor: 'primary.main' }}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
                  Ecosystem Builder
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Issuance + Verification + Trust" primaryTypographyProps={{ variant: 'body2' }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon fontSize="small" color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Optional: Authenticator, Kiosk" primaryTypographyProps={{ variant: 'body2' }} />
                  </ListItem>
                </List>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Best for: Government programs, trust networks
                </Typography>
                <Typography variant="body2" fontWeight="medium" color="success.dark" sx={{ mt: 1 }}>
                  Outcome: Operate a governed, multi-party identity ecosystem.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        {SHOW_PUBLIC_PRICING_BUTTONS && (
          <Box sx={{ textAlign: 'center', mt: 2 }}>
            <FutureFeatureButton
              size="small"
              disabled={DISABLE_PUBLIC_PRICING_BUTTONS}
              onClick={() => navigate('/pricing')}
              endIcon={<ArrowForwardIcon fontSize="small" />}
              disabledSx={{
                color: 'rgba(25, 118, 210, 0.52)',
              }}
            >
              Compare packages
            </FutureFeatureButton>
          </Box>
        )}
      </Box>

      {/* Who This Is For */}
      <Paper elevation={2} sx={{ p: 4, mb: 6, bgcolor: 'grey.50', borderRadius: 2 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom color="primary">
          Who This Is For
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
              Developers
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Start with Verification API (read-only checks), then add Issuance when you&apos;re ready to issue.
            </Typography>
            <Button size="small" onClick={() => navigate('/docs')} endIcon={<ArrowForwardIcon fontSize="small" />}>
              Read Docs
            </Button>
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
              Security & Compliance
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Use Kiosk for offline checkpoints and Verification API for policy-based checks with auditability.
            </Typography>
            <Button size="small" onClick={() => navigate('/standards')} endIcon={<ArrowForwardIcon fontSize="small" />}>
              Security model
            </Button>
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
              Product Managers
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Launch quickly with SaaS verification, expand to self-hosted issuance and wallets as needed.
            </Typography>
            {SHOW_PUBLIC_PRICING_BUTTONS && (
              <FutureFeatureButton
                size="small"
                disabled={DISABLE_PUBLIC_PRICING_BUTTONS}
                onClick={() => navigate('/pricing')}
                endIcon={<ArrowForwardIcon fontSize="small" />}
                disabledSx={{
                  color: 'rgba(25, 118, 210, 0.52)',
                }}
              >
                View Packages
              </FutureFeatureButton>
            )}
          </Grid>
        </Grid>
      </Paper>

      <Divider sx={{ my: 6 }} />

      {/* Products Grid */}
      <Typography variant="h4" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
        Our Products
      </Typography>

      <Grid container spacing={4}>
        {PRODUCTS.map((product) => (
          <Grid item xs={12} key={product.id} id={product.id} sx={{ scrollMarginTop: 96 }}>
            <Card elevation={3} sx={{ height: '100%', scrollMarginTop: 80 }}>
              <CardHeader
                title={product.name}
                subheader={product.tagline}
                titleTypographyProps={{ variant: 'h5', fontWeight: 'bold' }}
                subheaderTypographyProps={{ variant: 'subtitle1' }}
                sx={{ bgcolor: 'primary.main', color: 'white' }}
              />
              <CardContent>
                <Typography variant="body1" paragraph>
                  {product.description}
                </Typography>

                {/* Replaces/Extends Positioning */}
                {product.replacesExtends && (
                  <Typography 
                    variant="body2" 
                    sx={{ 
                      fontStyle: 'italic', 
                      color: 'text.secondary',
                      mb: 2,
                      pl: 2,
                      borderLeft: 2,
                      borderColor: 'primary.main'
                    }}
                  >
                    <strong>Replaces / Extends:</strong> {product.replacesExtends}
                  </Typography>
                )}

                {/* Outcome Callout */}
                <Paper 
                  elevation={0} 
                  sx={{ 
                    p: 2, 
                    mb: 3, 
                    bgcolor: 'success.light', 
                    borderLeft: 4, 
                    borderColor: 'success.main' 
                  }}
                >
                  <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                    What You Get:
                  </Typography>
                  <Typography variant="body2">
                    {product.id === 'verification-api' && 'Verify credentials in real-time with a REST API. Uses the trust registry (governed list of authorized issuers) to validate issuer trust. No PKI setup—just send credentials, get validation results.'}
                    {product.id === 'issuance-api' && 'Issue standards-based credentials in minutes. Control your signing keys and trust anchors. Works with standards-compliant wallets.'}
                    {product.id === 'kiosk' && 'Deploy offline verification at checkpoints. Offline mode validates signatures and cached trust anchors; revocation checks resume on reconnect.'}
                    {product.id === 'authenticator' && 'Give end users a standards-based wallet. Works with ISO 18013-5 and W3C VC issuers/verifiers that support supported OID4VP profiles.'}
                  </Typography>
                </Paper>

                {/* Deployment Options */}
                <Box sx={{ mb: 3 }}>
                  <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                    Deployment Options
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {product.deployment.map((option) => (
                      <Chip
                        key={option}
                        icon={DEPLOYMENT_ICONS[option]}
                        label={option}
                        variant="outlined"
                        color="primary"
                      />
                    ))}
                  </Box>
                </Box>

                <Grid container spacing={3}>
                  {/* Capabilities */}
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                      Core Capabilities
                    </Typography>
                    <List dense>
                      {product.capabilities.map((capability) => (
                        <ListItem key={capability} sx={{ py: 0 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            <CheckCircleIcon fontSize="small" color="success" />
                          </ListItemIcon>
                          <ListItemText primary={capability} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>

                  {/* Standards & Use Case */}
                  <Grid item xs={12} md={6}>
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                        Supported Standards
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {product.standards.map((standard) => (
                          <Chip
                            key={standard}
                            label={standard}
                            size="small"
                            color="secondary"
                          />
                        ))}
                      </Box>
                    </Box>

                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                        Pricing Model
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {product.pricing}
                      </Typography>
                    </Box>

                    <Box>
                      <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                        Target Use Cases
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {product.useCase}
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* CTA Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 4,
          mt: 6,
          px: 3,
          bgcolor: 'grey.50',
          borderRadius: 2,
          border: '1px solid',
          borderColor: 'grey.200',
        }}
      >
        <Chip label="Open Standard" color="primary" size="small" sx={{ fontWeight: 700, mb: 2 }} />
        <Typography variant="h5" fontWeight={700} gutterBottom>
          Built on an Open Protocol
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 700, mx: 'auto' }}>
          Every product is built on the Marty Identity Protocol (MIP)—an open, vendor-neutral specification.
          No vendor lock-in. No proprietary formats. Your identity infrastructure stays portable.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            onClick={() => navigate('/protocol')}
            endIcon={<ArrowForwardIcon />}
          >
            Explore the Protocol
          </Button>
          <Button
            variant="outlined"
            size="large"
            startIcon={<GitHubIcon />}
            href="https://github.com/mip-protocol/marty-protocol"
            target="_blank"
            rel="noopener noreferrer"
          >
            View on GitHub
          </Button>
        </Box>
      </Box>

      {/* CTA Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          mt: 8,
          bgcolor: 'grey.100',
          borderRadius: 2,
        }}
      >
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Ready to Build with {branding.branding.appName}?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
          {DISABLE_PUBLIC_PRICING_BUTTONS
            ? 'Pricing and onboarding are coming soon for production deployments. Explore the documentation and protocol details in the meantime.'
            : SHOW_PUBLIC_PRICING_BUTTONS
            ? 'Start free, or compare plans for enterprise deployment.'
            : 'Explore the documentation and protocol details while pricing and onboarding flows are still being developed.'}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          {SHOW_PUBLIC_PRICING_BUTTONS && (
            <FutureFeatureButton
              variant="contained"
              size="large"
              disabled={DISABLE_PUBLIC_PRICING_BUTTONS}
              onClick={() => navigate('/pricing')}
              disabledSx={{
                bgcolor: 'rgba(25, 118, 210, 0.14)',
                color: 'rgba(25, 118, 210, 0.52)',
              }}
            >
              Compare Plans
            </FutureFeatureButton>
          )}
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/docs')}
          >
            API Documentation
          </Button>
          <Button
            variant="text"
            size="large"
            onClick={() => navigate('/from-idv-to-verifiable-identity')}
            endIcon={<ArrowForwardIcon />}
          >
            Why Verifiable Identity
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default ProductPage;
