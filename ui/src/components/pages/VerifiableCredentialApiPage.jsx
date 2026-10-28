/**
 * Verifiable Credential API Page
 * 
 * SEO-optimized landing page for verifiable credential verification API
 * Primary keyword: "verifiable credential API"
 */

import { Box, Typography, Button, Card, CardContent, Grid, List, ListItem, ListItemIcon, ListItemText, Paper, Chip, Divider } from '@mui/material';
import { useNavigate } from 'react-router';
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
    description: 'The Marty verification component connects defined credential and document inputs to trust policies. Review exact release and profile support.',
    applicationCategory: 'SecurityApplication',
  });

  return (
    <Box>
      {/* SEO Meta Tags */}
      <SEOHead
        title="Verifiable Credential Verification API"
        description="Explore the Marty verification API for a defined credential or document workflow. Review release-specific formats, trust configuration, and customer-operated deployment."
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
          Evaluate defined credential and document checks in your environment
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
              Review Commercial Scope
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
          The Marty verification component connects a selected credential or document input to explicit trust and policy rules.
          Confirm the exact format, endpoint, issuer configuration, and release before integrating.
          Begin with synthetic data and retain both successful and rejected results.
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
                  Review the selected profile’s connectivity requirements, trust freshness limits, and failure behavior. Offline capability requires separate evidence.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Supported Formats */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
          Define the Credential Profile
        </Typography>
        <Typography variant="body1" sx={{ mb: 3 }}>
          These are profile areas to discuss, not a claim that every format is supported by every release.
          Verify the exact format version, proof mechanism, wallet, and acceptance rules you need.
        </Typography>
        <Grid container spacing={2}>
          {[
            { name: 'ISO 18013-5 mDoc', desc: "Mobile driver's licenses and mDocs" },
            { name: 'SD-JWT', desc: 'Selective disclosure JWT credentials' },
            { name: 'W3C VC JSON-LD', desc: 'Linked data verifiable credentials' },
            { name: 'Open Badges 3.0', desc: 'Education and workforce credentials' },
            { name: 'EUDI Wallet PID', desc: 'Person Identification Data (EU)' },
            { name: 'Custom Formats', desc: 'Review feasibility and separately scoped integration work' },
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

      {/* API Integration Review */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h3" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 4 }}>
          API Integration Review
        </Typography>
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <List>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Supported signature algorithms for the selected format" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Configured revocation and status handling" />
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
                <ListItemText primary="Disclosure validation for the selected profile" />
              </ListItem>
            </List>
          </Grid>
          <Grid item xs={12} md={6}>
            <List>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Exact OpenID4VP profile and wallet compatibility" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Profile requirements and test results" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Audit logging and reporting" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Documented REST endpoints" />
              </ListItem>
              <ListItem>
                <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                <ListItemText primary="Documented events and integration boundaries" />
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
                  Customer Operated
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Run the agreed verification scope with your own operations team.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <StorageIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Partner Operated
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Select a delivery partner and agree who owns hosting, keys, access, and maintenance.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Profile Evaluation
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Validate offline, air-gap, and headless requirements against the exact build; availability is not implied.
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
          Review the required specification version and profile against current implementation documentation and executed tests.
          Naming a standard does not establish compatibility, certification, or regulatory approval.
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
            ? 'Explore the documentation and define a synthetic evaluation for your workflow.'
            : SHOW_PUBLIC_PRICING_BUTTONS
            ? 'Discuss a bounded annual software license, with agreed scope, rights, and terms.'
            : 'Explore the API and documentation, then discuss the commercial scope your organization needs.'}
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
