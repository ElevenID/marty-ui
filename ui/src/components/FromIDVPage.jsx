/**
 * From IDV to Verifiable Identity Page
 * 
 * Thought-leadership page positioning ElevenID LLC as the evolution beyond
 * traditional identity verification (IDV) platforms
 */

import { Box, Typography, Paper, Card, CardContent, Grid, List, ListItem, ListItemIcon, ListItemText, Divider, Button } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useNavigate } from 'react-router-dom';
import { SEOHead } from './seo';
import { articleSchema, breadcrumbListSchema } from './seo/structuredData';
import { useBranding } from '../hooks/useBranding';

function FromIDVPage() {
  const navigate = useNavigate();
  const branding = useBranding();

  const infrastructurePrimitives = [
    {
      name: 'Trust Profiles',
      description: 'Who is authorized to issue or verify',
    },
    {
      name: 'Credential Templates',
      description: 'What claims exist and how they are structured',
    },
    {
      name: 'Presentation Policies',
      description: 'What must be disclosed, and when',
    },
    {
      name: 'Deployment Profiles',
      description: 'Where and how identity flows operate',
    },
  ];

  const implementations = [
    'Issue credentials using W3C VC, SD-JWT, and ISO formats—portable across wallets and ecosystems',
    'Verify wallet-presented credentials instead of re-running document checks',
    'Govern trust centrally through auditable trust registries',
    'Support selective disclosure and data minimization by design',
  ];

  const audiences = [
    {
      title: 'Governments',
      urgency: 'Required to accept EUDI wallets—need trust governance now.',
      points: [
        'EUDI Wallet compatibility',
        'Cross-border credential acceptance',
      ],
    },
    {
      title: 'Enterprises',
      urgency: 'Re-verification costs are rising—reuse is the only way out.',
      points: [
        'Reduced repeat KYC costs',
        'Identity reuse across partners',
      ],
    },
    {
      title: 'Platforms & Issuers',
      urgency: 'Credentials are becoming products—portability matters.',
      points: [
        'Workforce and education credentials',
        'Portable identity products',
      ],
    },
    {
      title: 'Developers',
      urgency: 'Identity is becoming infrastructure—build once, integrate everywhere.',
      points: [
        'Open APIs and SDKs',
        'Flexible deployment models',
      ],
    },
  ];

  return (
    <Box>
      <SEOHead
        title="Why Verifiable Identity"
        description="Why traditional identity verification is evolving into verifiable credential infrastructure with reusable trust, standards, and governance."
        canonicalPath="/why-verifiable-identity"
        keywords={['identity verification', 'verifiable identity', 'IDV modernization', 'reusable trust infrastructure']}
        structuredData={[
          articleSchema({
            headline: 'Why Verifiable Identity',
            description: 'Why traditional identity verification is evolving into verifiable credential infrastructure with reusable trust, standards, and governance.',
            datePublished: '2024-01-01',
            url: 'https://elevenidllc.com/why-verifiable-identity',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'Why Verifiable Identity', url: 'https://elevenidllc.com/why-verifiable-identity' },
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
          From Identity Verification to Verifiable Identity
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 900, mx: 'auto', opacity: 0.95, mb: 2 }}>
          Traditional identity verification was built for onboarding.
          Modern digital identity must support <strong>reuse, portability, and trust at scale</strong>.
        </Typography>
        <Typography variant="body1" sx={{ maxWidth: 900, mx: 'auto', opacity: 0.9 }}>
          ElevenID LLC provides the infrastructure layer that replaces repeated identity checks with{' '}
          <strong>cryptographically verifiable credentials</strong> — designed for EUDI Wallets, Open Badges,
          and enterprise trust ecosystems.
        </Typography>
      </Box>

      {/* Section 1 - The IDV Plateau */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Identity verification solves onboarding. It does not solve identity.
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
          IDV platforms answer one question: &ldquo;Is this person real right now?&rdquo; 
          They do this well—but verification outcomes aren&apos;t reusable, trust decisions are locked in vendor systems, 
          and costs scale linearly.
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, fontWeight: 500 }}>
          Digital identity requires something different: credentials that can be issued once and verified anywhere.
        </Typography>
      </Box>

      <Divider sx={{ my: 8 }} />

      {/* Section 2 - What Changed */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Wallets, credentials, and regulation changed the rules
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
          Governments and platforms now adopt digital wallets where users hold credentials directly. 
          Standards like W3C Verifiable Credentials and ISO 18013-5 define how claims are issued, stored, and verified. 
          The EUDI Wallet requires private-sector verifiers to accept government-issued credentials.
        </Typography>
        <Paper elevation={2} sx={{ p: 3, mt: 3, bgcolor: 'primary.light', color: 'primary.contrastText' }}>
          <Typography variant="h6" textAlign="center">
            Identity decisions must be <strong>verifiable, portable, and interoperable</strong>—not vendor-owned.
          </Typography>
        </Paper>
      </Box>

      <Divider sx={{ my: 8 }} />

      {/* Section 3 - The Missing Layer in Most IDV Platforms */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          The Missing Layer in Most IDV Platforms
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom sx={{ mb: 4 }}>
          Verification is not enough — trust must be governed
        </Typography>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
          Traditional IDV platforms focus on:
        </Typography>
        <List>
          {['Document authenticity', 'Biometric matching', 'Fraud detection'].map((item, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <CheckCircleIcon color="action" />
              </ListItemIcon>
              <ListItemText primary={item} />
            </ListItem>
          ))}
        </List>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mt: 3 }}>
          What they lack is <strong>identity orchestration</strong>.
        </Typography>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mb: 3 }}>
          At scale, digital identity requires four governed primitives:
        </Typography>

        <Grid container spacing={3}>
          {infrastructurePrimitives.map((primitive, index) => (
            <Grid item xs={12} sm={6} key={index}>
              <Card elevation={2}>
                <CardContent>
                  <Typography variant="h6" fontWeight="bold" gutterBottom color="primary">
                    • {primitive.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {primitive.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mt: 4 }}>
          These primitives must be orchestrated by <strong>flows</strong> that work across wallets, APIs,
          kiosks, and offline environments.
        </Typography>

        <Paper elevation={2} sx={{ p: 3, mt: 3, bgcolor: 'grey.100', borderRadius: 2 }}>
          <Typography variant="body1" sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
            <strong>This is the same model used throughout ElevenID LLC.</strong>{' '}
            Digital identity becomes scalable when trust, policy, and deployment are modeled as configuration—then 
            orchestrated by flows across wallets, APIs, and devices.
          </Typography>
        </Paper>
      </Box>

      <Divider sx={{ my: 8 }} />

      {/* Section 4 - How ElevenID LLC Solves Identity Management */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          How {branding.branding.appName} Solves Identity Management
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom sx={{ mb: 4 }}>
          {branding.branding.appName} is identity infrastructure, not a point solution
        </Typography>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mb: 3 }}>
          {branding.branding.appName} implements the missing orchestration layer required for modern digital identity:
        </Typography>

        <List>
          {implementations.map((item, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <CheckCircleIcon color="success" />
              </ListItemIcon>
              <ListItemText 
                primary={item}
                primaryTypographyProps={{ fontSize: '1.05rem' }}
              />
            </ListItem>
          ))}
        </List>

        <Paper elevation={2} sx={{ p: 4, mt: 4, bgcolor: 'success.light', color: 'success.contrastText' }}>
          <Typography variant="h6" textAlign="center" fontWeight="bold">
            Rather than producing a one-time verification decision, {branding.branding.appName} enables{' '}
            <strong>reusable trust</strong>.
          </Typography>
        </Paper>
      </Box>

      <Divider sx={{ my: 8 }} />

      {/* Section 5 - Who This Is For */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          Who This Is For
        </Typography>
        <Typography variant="h6" color="text.secondary" textAlign="center" gutterBottom sx={{ mb: 4 }}>
          Built for organizations preparing for what comes next
        </Typography>

        <Grid container spacing={4}>
          {audiences.map((audience, index) => (
            <Grid item xs={12} sm={6} md={3} key={index}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Typography variant="h6" fontWeight="bold" gutterBottom color="primary">
                    {audience.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontStyle: 'italic' }}>
                    {audience.urgency}
                  </Typography>
                  <List dense>
                    {audience.points.map((point, idx) => (
                      <ListItem key={idx} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon fontSize="small" color="success" />
                        </ListItemIcon>
                        <ListItemText 
                          primary={point}
                          primaryTypographyProps={{ variant: 'body2' }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      <Divider sx={{ my: 8 }} />

      {/* Section 6 - The Outcome */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          The Outcome
        </Typography>
        <Typography variant="h6" color="text.secondary" textAlign="center" gutterBottom sx={{ mb: 4 }}>
          From one-time verification to reusable, governed identity
        </Typography>

        <Paper elevation={3} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <Typography variant="h5" sx={{ textAlign: 'center', fontWeight: 'bold', color: 'primary.main', my: 2 }}>
            Credentials are issued once, then verified anywhere—without re-verification.
          </Typography>
        </Paper>
      </Box>

      {/* Call to Action */}
      <Box 
        sx={{ 
          textAlign: 'center', 
          py: 6, 
          bgcolor: 'grey.100', 
          borderRadius: 2,
        }}
      >
        <Typography variant="h5" gutterBottom fontWeight="bold">
          Ready to move beyond traditional IDV?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4, maxWidth: 600, mx: 'auto' }}>
          Start with the verification surface, then go deeper into the API and docs when you&apos;re ready to implement.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            onClick={() => navigate('/developers')}
            endIcon={<ArrowForwardIcon />}
            sx={{ px: 4 }}
          >
            Start Verifying Credentials
          </Button>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/verifiable-credential-api')}
            sx={{ px: 4 }}
          >
            View Verification API
          </Button>
          <Button
            variant="text"
            size="large"
            onClick={() => navigate('/docs')}
          >
            API Docs
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default FromIDVPage;
