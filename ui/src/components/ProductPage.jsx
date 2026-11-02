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
import StorageIcon from '@mui/icons-material/Storage';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import ComputerIcon from '@mui/icons-material/Computer';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import SecurityIcon from '@mui/icons-material/Security';
import AccountBalanceWalletIcon from '@mui/icons-material/AccountBalanceWallet';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import GitHubIcon from '@mui/icons-material/GitHub';
import { useNavigate } from 'react-router';
import { DISABLE_PUBLIC_PRICING_BUTTONS, SHOW_PUBLIC_PRICING_BUTTONS } from '@ui-public-config';
import FutureFeatureButton from './FutureFeatureButton';
import { PRODUCTS } from '../data/marketingContent';
import { useBranding } from '../hooks/useBranding';

const DEPLOYMENT_ICONS = {
  'Customer-operated': <StorageIcon />,
  'Profile evaluation': <ComputerIcon />,
  'On-site application': <ComputerIcon />,
  'Build-specific platforms': <PhoneAndroidIcon />,
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
        description="Marty: one customer-operated product for portable credentials, applicant and document verification, and Travel Trust. Review components, scope, and operating responsibilities."
        canonicalPath="/product"
        keywords={['verifiable credential API', 'EUDI Wallet API', 'Open Badges API', 'ISO 18013-5', 'credential issuance', 'credential verification']}
        structuredData={[
          softwareApplicationSchema({
            name: 'Marty by ElevenID',
            description: 'Customer-operated identity workflows with defined release, integration, and commercial scope.',
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
          Marty: Workflows, Components, and APIs
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          Choose a useful workflow, evaluate the relevant release, and agree the scope your organization needs.
        </Typography>
      </Box>
      {/* Product Overview */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="body1" color="text.secondary" paragraph sx={{ maxWidth: 900, mx: 'auto', textAlign: 'center' }}>
          Marty by {branding.branding.appName} connects credentials, document checks, trust policies, and workflow decisions.
          Start with synthetic data and validate the selected release in your operating environment.
        </Typography>
      </Box>
      {/* Start Here Router */}
      <Paper elevation={2} sx={{ p: 4, mb: 6, bgcolor: 'grey.50', borderRadius: 2 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom textAlign="center">
          What are you doing first?
        </Typography>
        <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mb: 3 }}>
          Start with the component your selected workflow needs.
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
      {/* One product, independent use cases */}
      <Box sx={{ mb: 6 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom>
          One Marty Product, Three Use Cases
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: 'Portable Credentials', description: 'Evaluate issuance, holding, presentation, and verification for a defined credential and trust network.' },
            { title: 'Applicant and Document Verification', description: 'Connect document inputs, review rules, and recorded decisions to your application workflow.' },
            { title: 'Travel Trust', description: 'Evaluate travel-document trust, journey rules, and verification decisions for a defined travel scenario.' },
          ].map((track) => (
            <Grid item xs={12} md={4} key={track.title}>
              <Card elevation={2} sx={{ height: '100%' }}>
                <CardContent>
                  <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>{track.title}</Typography>
                  <Typography variant="body2" color="text.secondary">{track.description}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
        <Typography variant="body1" sx={{ mt: 3 }}>
          Each use case can be evaluated independently. An agreed license may cover named workflows from one or more use cases.
          Direct customers and partner/OEM teams use the same product foundation.
        </Typography>
        <Typography variant="body1" sx={{ mt: 2 }}>
          The default commercial direction is a bounded annual software license, with founding access discussed on request.
          Price, included workflows, distribution rights, and delivery terms require an agreed offer.
          Integration or other custom work is separately scoped.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          Your organization or your selected partner runs production. The software offer does not include managed production,
          installation or support hours, guaranteed response or resolution times, an uptime SLA, or 24/7 service.
          Use the repository&apos;s documented issue and vulnerability reporting channels.
        </Typography>
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
              Review the documented interfaces and test inputs, results, and failure cases in your configured environment.
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
              Review trust sources, data handling, and evidence for the specific release and deployment profile.
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
              Define the use case and operator, then evaluate Marty directly or with your chosen delivery partner.
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
                Review Commercial Scope
              </FutureFeatureButton>
            )}
          </Grid>
        </Grid>
      </Paper>
      <Divider sx={{ my: 6 }} />
      {/* Products Grid */}
      <Typography variant="h4" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
        Marty Components
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
                    What to Evaluate:
                  </Typography>
                  <Typography variant="body2">
                    {product.id === 'verification-api' && 'Configure issuer trust and a presentation policy, then test the documented verification endpoint with authorized synthetic credentials.'}
                    {product.id === 'issuance-api' && 'Test the chosen credential template, issuer, signing keys, and recipient wallet together.'}
                    {product.id === 'kiosk' && 'Validate the selected device, transport, trust freshness limits, and behavior when connectivity is unavailable.'}
                    {product.id === 'authenticator' && 'Evaluate the exact wallet build and platform against the selected issuance and presentation profiles.'}
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
                      Component Scope
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
                        Scope References
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
                        Commercial Scope
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
        <Chip label="Open Draft Protocol" color="primary" size="small" sx={{ fontWeight: 700, mb: 2 }} />
        <Typography variant="h5" fontWeight={700} gutterBottom>
          Built on an Open Protocol
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 700, mx: 'auto' }}>
          Marty uses the Marty Identity Protocol (MIP), an open draft specification.
          Review the versioned mappings and test each integration; a protocol reference does not certify a deployment.
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
            href="https://github.com/Marty-Protocol/Marty-Protocol"
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
            ? 'Explore the documentation and discuss the workflow, release, and operating responsibilities your organization needs.'
            : SHOW_PUBLIC_PRICING_BUTTONS
            ? 'Discuss the defined annual license scope and terms for your organization.'
            : 'Explore the documentation and discuss a defined evaluation.'}
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
              Review Commercial Scope
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
