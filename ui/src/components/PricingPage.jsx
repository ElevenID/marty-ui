/**
 * Pricing Page
 * 
 * Dedicated pricing page showing all plan tiers
 * Extracted from LandingPage for better separation of concerns
 */

import { Box, Typography, Button, Card, CardContent, CardHeader, CardActions, Grid, Divider, List, ListItem, ListItemIcon, ListItemText, Chip, Paper } from '@mui/material';
import { SEOHead } from './seo';
import CheckIcon from '@mui/icons-material/Check';
import CloseIcon from '@mui/icons-material/Close';
import StarIcon from '@mui/icons-material/Star';
import LockIcon from '@mui/icons-material/Lock';
import { useAuth } from '../hooks/useAuth';
import { INFRASTRUCTURE_VALUE } from '../data/marketingContent';

/**
 * Pricing tier configuration
 * Mirrors PLAN_LIMITS in packages/marty_common/plans.py
 *
 * Billing is aligned with the protocol: verifications and issued credentials
 * are the primary metered units. No per-API-call pricing.
 */
const PRICING_TIERS = [
  {
    name: 'FREE',
    displayName: 'The Sandbox',
    focus: 'Experiment with Standards',
    price: 0,
    description: 'All OID4VCI / OID4VP features enabled. No protocol gating.',
    keySpecs: '500 Verifications/mo + 50 Issued Credentials',
    features: [
      { text: '500 verifications/month', included: true },
      { text: '50 issued credentials/month', included: true },
      { text: 'Up to 5 team members', included: true },
      { text: '3 credential templates', included: true },
      { text: 'All protocol features (OID4VCI/OID4VP)', included: true },
      { text: 'ZK proof verification', included: true },
      { text: 'Custom branding', included: false },
      { text: 'Webhooks', included: false },
      { text: 'Audit logs', included: false },
    ],
    buttonText: 'Start Free',
    highlighted: false,
  },
  {
    name: 'STARTER',
    displayName: 'The Launchpad',
    focus: 'First Production App',
    price: 99,
    description: 'Custom branding and presentation policies. Stop paying $1.50 per check.',
    keySpecs: '1,000 Verifications included + Unlimited Templates',
    features: [
      { text: '1,000 verifications/month', included: true },
      { text: '500 issued credentials/month', included: true },
      { text: 'Up to 25 team members', included: true },
      { text: 'Unlimited credential templates', included: true },
      { text: 'Custom branding', included: true },
      { text: 'Webhooks', included: true },
      { text: 'Audit logs', included: true },
      { text: 'Priority email support', included: true },
      { text: 'Multi-environment', included: false },
    ],
    buttonText: 'Get Started',
    highlighted: false,
  },
  {
    name: 'PROFESSIONAL',
    displayName: 'The Trust Fabric',
    focus: 'Multi-App Orchestration',
    price: 399,
    description: 'Audit-ready logs and multi-environment management. Built for scale.',
    keySpecs: '10,000 Verifications included + Priority SLA',
    features: [
      { text: '10,000 verifications/month', included: true },
      { text: '5,000 issued credentials/month', included: true },
      { text: 'Up to 100 team members', included: true },
      { text: 'Multi-environment management', included: true },
      { text: 'Custom Cedar policies', included: true },
      { text: 'Kiosk device registration', included: true },
      { text: 'Priority SLA support', included: true },
      { text: 'Everything in Starter', included: true },
      { text: 'Self-hosted deployment', included: false },
    ],
    buttonText: 'Go Professional',
    highlighted: true,
  },
  {
    name: 'ENTERPRISE',
    displayName: 'The Sovereign Choice',
    focus: 'Your Trust, Your Infrastructure',
    price: null, // Custom pricing
    description: 'Air-gapped deployments, dedicated data residency, and 24/7 support.',
    keySpecs: 'Unlimited everything + Self-hosted options',
    features: [
      { text: 'Unlimited verifications', included: true },
      { text: 'Unlimited issued credentials', included: true },
      { text: 'Unlimited team members', included: true },
      { text: 'Self-hosted deployment options', included: true },
      { text: 'SCIM provisioning', included: true },
      { text: 'Dedicated support + 24/7 SLA', included: true },
      { text: 'Air-gapped & data residency', included: true },
      { text: 'Everything in Professional', included: true },
    ],
    buttonText: 'Contact Sales',
    highlighted: false,
  },
];

const HIRE_DEVELOPER_TIER = {
  name: 'HIRE THE DEVELOPER',
  tagline: "It's not too much, you just can't afford it.",
  priceAnnual: 200000,
  priceUpfront: 180000, // 10% discount for full payment upfront
  description: 'Skip the product, hire the architect.',
  features: [
    { text: 'Direct access to the developer', included: true },
    { text: 'Feature requests implemented within 24h', included: true },
    { text: 'Personal Slack channel', included: true },
    { text: 'Monthly architecture reviews', included: true },
    { text: 'Code written exactly how you like it', included: true },
    { text: 'Judgemental comments about your tech choices', included: true },
    { text: 'Unlimited opinions', included: true },
  ],
  comingSoon: true,
};

function PricingPage() {
  const { login } = useAuth();

  return (
    <Box>
      <SEOHead
        title="Verifiable Credential Pricing"
        description="Transparent pricing for verifiable credential infrastructure. Free, Starter, Professional, and Enterprise plans for issuance and verification APIs."
        canonicalPath="/pricing"
        keywords={['verifiable credential pricing', 'credential API pricing', 'identity verification pricing', 'EUDI wallet infrastructure pricing']}
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
          Unlimited Verification. Zero Per-Event Fees.
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          Every plan includes full OID4VCI &amp; OID4VP protocol support.
          Pick a tier based on volume, not features.
        </Typography>
      </Box>

      {/* Plan Comparison */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
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
                title={tier.displayName || tier.name}
                subheader={tier.focus}
                titleTypographyProps={{ align: 'center', fontWeight: 'bold' }}
                subheaderTypographyProps={{ align: 'center', fontStyle: 'italic' }}
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
                
                {/* Key Specs + Differentiator */}
                <Paper elevation={0} sx={{ p: 2, mb: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                  {tier.keySpecs && (
                    <Typography variant="body2" fontWeight="bold" sx={{ mb: 0.5 }}>
                      {tier.keySpecs}
                    </Typography>
                  )}
                  <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                    {tier.description}
                  </Typography>
                </Paper>

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

      {/* Hire the Developer — Coming Soon */}
      <Box sx={{ position: 'relative', mb: 6, mt: 2 }}>
        {/* Coming Soon Overlay */}
        <Box
          sx={{
            position: 'absolute',
            inset: 0,
            zIndex: 2,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: 2,
            pointerEvents: 'none',
          }}
        >
          <Chip
            icon={<LockIcon />}
            label="COMING SOON"
            sx={{
              fontSize: '1rem',
              fontWeight: 'bold',
              px: 3,
              py: 2.5,
              height: 'auto',
              bgcolor: 'warning.main',
              color: 'warning.contrastText',
              boxShadow: 6,
              letterSpacing: 2,
              '& .MuiChip-icon': { fontSize: '1.3rem', color: 'warning.contrastText' },
            }}
          />
        </Box>

        {/* Card — shaded out */}
        <Card
          sx={{
            opacity: 0.45,
            filter: 'grayscale(60%)',
            border: 2,
            borderColor: 'grey.400',
            borderStyle: 'dashed',
            borderRadius: 2,
            userSelect: 'none',
            pointerEvents: 'none',
          }}
        >
          <CardContent>
            <Grid container spacing={4} alignItems="center">
              {/* Left: headline + pricing */}
              <Grid item xs={12} md={5}>
                <Typography
                  variant="overline"
                  fontWeight="bold"
                  color="text.secondary"
                  letterSpacing={3}
                >
                  {HIRE_DEVELOPER_TIER.name}
                </Typography>
                <Typography variant="h4" fontWeight="bold" gutterBottom>
                  {HIRE_DEVELOPER_TIER.description}
                </Typography>
                <Typography
                  variant="body1"
                  color="text.secondary"
                  sx={{ fontStyle: 'italic', mb: 3 }}
                >
                  &ldquo;{HIRE_DEVELOPER_TIER.tagline}&rdquo;
                </Typography>

                {/* Annual price */}
                <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, mb: 1 }}>
                  <Typography variant="h3" fontWeight="bold">
                    ${HIRE_DEVELOPER_TIER.priceAnnual.toLocaleString()}
                  </Typography>
                  <Typography variant="subtitle1" color="text.secondary">/year</Typography>
                </Box>

                {/* Upfront discount */}
                <Paper
                  elevation={0}
                  sx={{ p: 1.5, bgcolor: 'success.light', borderRadius: 1, display: 'inline-block' }}
                >
                  <Typography variant="body2" fontWeight="bold" color="success.dark">
                    Pay upfront &amp; save 10% — ${HIRE_DEVELOPER_TIER.priceUpfront.toLocaleString()}/year
                  </Typography>
                </Paper>
              </Grid>

              {/* Right: features */}
              <Grid item xs={12} md={7}>
                <Divider orientation="vertical" flexItem sx={{ display: { xs: 'none', md: 'block' } }} />
                <List dense>
                  {HIRE_DEVELOPER_TIER.features.map((feature, index) => (
                    <ListItem key={index} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckIcon fontSize="small" color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary={feature.text}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>
                <Button variant="contained" color="secondary" disabled fullWidth sx={{ mt: 2 }}>
                  Apply to Hire
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Box>

      {/* FAQ / Additional Info */}
      <Box sx={{ mt: 8 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom textAlign="center">
          Frequently Asked Questions
        </Typography>

        <Grid container spacing={3} sx={{ mt: 2 }}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  What&apos;s included in the free tier?
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  500 verifications and 50 credential issuances per month with full protocol support.
                  Every OID4VCI and OID4VP feature is enabled — no &ldquo;Standard vs Pro&rdquo; gating.
                  No credit card required.
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  What&apos;s NOT limited?
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Protocol features are never gated by plan. All tiers get OID4VCI, OID4VP,
                  ZK proof verification, mDL/mDocs, and verifiable credential support.
                  We meter by verifications and issuances — not API calls.
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  Can I upgrade or downgrade?
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Yes, you can change your plan at any time. Upgrades take effect immediately, 
                  and downgrades will be applied at the next billing cycle.
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  What payment methods do you accept?
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  We accept all major credit cards. Enterprise customers can arrange for 
                  invoice billing with NET30 terms.
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  What about self-hosted deployments?
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Self-hosted options are available for Enterprise customers. Contact sales 
                  to discuss licensing, support, and deployment options.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>

      {/* Infrastructure Value Proposition */}
      <Paper elevation={3} sx={{ p: 4, mb: 8, bgcolor: 'primary.light', borderRadius: 2 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" color="primary.dark" textAlign="center">
          {INFRASTRUCTURE_VALUE.title}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          Traditional IDV platforms charge $1–$3 per verification. ElevenID charges a flat monthly rate 
          with included verifications — aligned with the protocol, not per-event friction.
        </Typography>
        <Grid container spacing={3}>
          {INFRASTRUCTURE_VALUE.points.map((point, index) => (
            <Grid item xs={12} sm={6} md={3} key={index}>
              <Card elevation={0} sx={{ bgcolor: 'white', height: '100%' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <CheckIcon color="success" />
                    <Typography variant="body1" fontWeight="500">
                      {point}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {/* CTA */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          mt: 8,
          bgcolor: 'grey.100',
          borderRadius: 2,
        }}
      >
        <Typography variant="h5" gutterBottom>
          Ready to get started?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Sign up today and start issuing secure digital credentials
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            onClick={() => login()}
            sx={{ px: 4 }}
          >
            Start Free Trial
          </Button>
          <Button
            variant="outlined"
            size="large"
            onClick={() => window.location.href = 'mailto:sales@elevenid.com'}
            sx={{ px: 4 }}
          >
            Contact Sales
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default PricingPage;
