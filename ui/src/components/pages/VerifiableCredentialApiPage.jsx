/**
 * Verifiable Credential API Page
 * 
 * SEO-optimized landing page for verifiable credential verification API
 * Primary keyword: "verifiable credential API"
 */

import { Box, Typography, Button, Card, CardContent, Grid, List, ListItem, ListItemIcon, ListItemText, Paper, Chip, Divider } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import {
  DISABLE_PUBLIC_GET_STARTED_BUTTONS,
  DISABLE_PUBLIC_PRICING_BUTTONS,
  SHOW_PUBLIC_GET_STARTED_BUTTONS,
  SHOW_PUBLIC_PRICING_BUTTONS,
} from '@ui-public-config';
import { SEOHead, softwareApplicationSchema } from '../seo';
import FutureFeatureButton from '../FutureFeatureButton';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import CloudIcon from '@mui/icons-material/Cloud';
import StorageIcon from '@mui/icons-material/Storage';
import SecurityIcon from '@mui/icons-material/Security';
import SpeedIcon from '@mui/icons-material/Speed';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

function VerifiableCredentialApiPage() {
  const navigate = useNavigate();

  const structuredData = softwareApplicationSchema({
    name: 'Verifiable Credential Verification API',
    description: 'Enterprise API for verifying W3C Verifiable Credentials, EUDI Wallet credentials, ISO 18013-5 mDocs, SD-JWTs, and Open Badges 3.0 with governed trust registries.',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Cross-platform',
    offers: {
      pricingModel: 'PER_USE',
      price: '0',
      priceCurrency: 'USD',
    },
  });

  return (
    <Box>
      {/* SEO Meta Tags */}
      <SEOHead
        title="Verifiable Credential Verification API"
        description="Verify W3C Verifiable Credentials, EUDI Wallet credentials, ISO 18013-5 mDocs, SD-JWTs, and Open Badges with cryptographic validation and governed trust registries."
        canonicalPath="/verifiable-credential-api"
        structuredData={structuredData}
        keywords={[
          'verifiable credential API',
          'W3C VC verification',
          'credential verification API',
          'EUDI Wallet API',
          'ISO 18013-5 verification',
          'SD-JWT verification',
          'Open Badges verification',
          'trust registry API',
        ]}
      />

      {/* Hero Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 8,
          mb: 6,
          background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Typography variant="h2" component="h1" gutterBottom fontWeight="bold">
          Verifiable Credential Verification API
        </Typography>
        <Typography variant="h5" sx={{ mb: 4, opacity: 0.95 }}>
          Cryptographically verify W3C Verifiable Credentials at scale
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          {SHOW_PUBLIC_GET_STARTED_BUTTONS && (
            <FutureFeatureButton
              variant="contained"
              size="large"
              disabled={DISABLE_PUBLIC_GET_STARTED_BUTTONS}
              sx={{ bgcolor: 'white', color: 'primary.main', '&:hover': { bgcolor: 'grey.100' } }}
              onClick={() => navigate('/pricing')}
              disabledSx={{
                bgcolor: 'rgba(255, 255, 255, 0.16)',
                color: 'rgba(255, 255, 255, 0.62)',
                border: '1px solid rgba(255, 255, 255, 0.18)',
              }}
            >
              Start Free
            </FutureFeatureButton>
          )}
          <Button
            variant="outlined"
            size="large"
            sx={{ borderColor: 'white', color: 'white', '&:hover': { borderColor: 'grey.100', bgcolor: 'rgba(255,255,255,0.1)' } }}
            onClick={() => navigate('/docs')}
          >
            View API Docs
          </Button>
        </Box>
      </Box>

      {/* What It Does */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" textAlign="center" sx={{ mb: 4 }}>
          Replace Repeated IDV with Reusable Trust
        </Typography>
        <Typography variant="body1" sx={{ mb: 4, textAlign: 'center', maxWidth: '800px', mx: 'auto', fontSize: '1.1rem' }}>
          The Verifiable Credential Verification API validates cryptographically signed credentials from EUDI Wallets, 
          mobile driver's licenses (ISO 18013-5), Open Badges, and other W3C VC formats. Verification decisions are 
          governed centrally via trust registries — no per-verifier configuration required.
        </Typography>

        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <VerifiedUserIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom fontWeight="bold">
                  Cryptographic Validation
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Verify digital signatures, check revocation status, validate issuer authorization, and enforce trust policies.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <AccountTreeIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom fontWeight="bold">
                  Governed Trust Registries
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Trust decisions managed centrally. Add or remove authorized issuers without changing verifier code.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <SpeedIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom fontWeight="bold">
                  Offline & Online
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Verify credentials with or without network connectivity. Cryptographic proofs work anywhere.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Supported Formats */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
          Verify Multiple Credential Formats
        </Typography>
        <Grid container spacing={2}>
          {[
            { name: 'ISO 18013-5 mDoc', desc: "Mobile driver's licenses and mDocs" },
            { name: 'SD-JWT', desc: 'Selective disclosure JWT credentials' },
            { name: 'W3C VC JSON-LD', desc: 'Linked data verifiable credentials' },
            { name: 'Open Badges 3.0', desc: 'Education and workforce credentials' },
            { name: 'EUDI Wallet PID', desc: 'Person Identification Data (EU)' },
            { name: 'Custom Formats', desc: 'Extend with your own credential types' },
          ].map((format, idx) => (
            <Grid item xs={12} sm={6} md={4} key={idx}>
              <Paper sx={{ p: 3, height: '100%' }}>
                <Typography variant="h6" gutterBottom>
                  {format.name}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {format.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* API Features */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
          API Features
        </Typography>
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <List>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Signature verification (ECDSA, EdDSA, RSA)" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Revocation and status list checking" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Issuer authorization via trust registries" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Presentation policy enforcement" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Selective disclosure validation (SD-JWT)" />
              </ListItem>
            </List>
          </Grid>
          <Grid item xs={12} md={6}>
            <List>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="OpenID4VP protocol support" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Compliance profile validation" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Audit logging and reporting" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="REST and GraphQL interfaces" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Webhook notifications" />
              </ListItem>
            </List>
          </Grid>
        </Grid>
      </Box>

      {/* Deployment Options */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
          Deployment Options
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <CloudIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  SaaS
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Hosted multi-tenant verification endpoint. Start in minutes.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <StorageIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Self-Hosted
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Deploy in your own cloud or data center. Full control.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  On-Premise
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Air-gapped environments for government and high-security use cases.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Use Cases */}
      <Box sx={{ mb: 8, bgcolor: 'grey.50', p: 4, borderRadius: 2 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
          Use Cases
        </Typography>
        <Grid container spacing={3}>
          {[
            { title: 'Airport Identity Verification', desc: 'Verify travel credentials and government IDs', link: '/solutions/airport-identity-verification' },
            { title: 'Workforce Credentials', desc: 'Validate employee certifications and badges', link: '/solutions/workforce-credential-verification' },
            { title: 'Education Credentials', desc: 'Verify diplomas, transcripts, and certificates', link: '/solutions/education-credential-verification' },
            { title: 'Age Verification', desc: 'Check age credentials without revealing birthdates', link: '/solutions/age-verification-wallet' },
          ].map((useCase, idx) => (
            <Grid item xs={12} sm={6} key={idx}>
              <Paper sx={{ p: 3, height: '100%', cursor: 'pointer', '&:hover': { boxShadow: 4 } }} onClick={() => navigate(useCase.link)}>
                <Typography variant="h6" gutterBottom>
                  {useCase.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {useCase.desc}
                </Typography>
                <Typography variant="body2" color="primary">
                  Learn more <ArrowForwardIcon sx={{ fontSize: 14, verticalAlign: 'middle' }} />
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* Standards */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
          Built on Open Standards
        </Typography>
        <Typography variant="body1" sx={{ mb: 3 }}>
          The Verifiable Credential API is built on W3C Verifiable Credentials, OpenID4VP, and ISO 18013-5 standards.
          This ensures long-term interoperability and vendor independence.
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {['W3C VC 1.1', 'W3C VC 2.0', 'ISO 18013-5', 'OpenID4VP', 'SD-JWT', 'Open Badges 3.0', 'EUDI ARF'].map(std => (
            <Chip key={std} label={std} color="primary" variant="outlined" />
          ))}
        </Box>
        <Button sx={{ mt: 3 }} endIcon={<ArrowForwardIcon />} onClick={() => navigate('/standards')}>
          View Standards Architecture
        </Button>
      </Box>

      {/* CTA Footer */}
      <Paper sx={{ p: 6, textAlign: 'center', bgcolor: 'primary.main', color: 'white' }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Start Verifying Verifiable Credentials
        </Typography>
        <Typography variant="body1" sx={{ mb: 4, opacity: 0.9 }}>
          {DISABLE_PUBLIC_PRICING_BUTTONS
            ? 'Pricing and onboarding are coming soon for production deployments. Explore the API and documentation in the meantime.'
            : SHOW_PUBLIC_PRICING_BUTTONS
            ? 'Free tier available. No credit card required.'
            : 'Explore the API and documentation while pricing access is being finalized.'}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          {SHOW_PUBLIC_PRICING_BUTTONS && (
            <FutureFeatureButton
              variant="contained"
              size="large"
              disabled={DISABLE_PUBLIC_PRICING_BUTTONS}
              sx={{ bgcolor: 'white', color: 'primary.main', '&:hover': { bgcolor: 'grey.100' } }}
              onClick={() => navigate('/pricing')}
              disabledSx={{
                bgcolor: 'rgba(255, 255, 255, 0.16)',
                color: 'rgba(255, 255, 255, 0.62)',
                border: '1px solid rgba(255, 255, 255, 0.18)',
              }}
            >
              View Pricing
            </FutureFeatureButton>
          )}
          <Button
            variant="outlined"
            size="large"
            sx={{ borderColor: 'white', color: 'white', '&:hover': { borderColor: 'grey.100', bgcolor: 'rgba(255,255,255,0.1)' } }}
            onClick={() => navigate('/docs')}
          >
            API Documentation
          </Button>
        </Box>
      </Paper>
    </Box>
  );
}

export default VerifiableCredentialApiPage;
