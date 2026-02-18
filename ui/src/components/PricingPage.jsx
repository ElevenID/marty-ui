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
import { useAuth } from '../hooks/useAuth';
import { INFRASTRUCTURE_VALUE } from '../data/marketingContent';

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
          Pricing Plans
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          Choose the plan that fits your organization&apos;s needs
        </Typography>
      </Box>

      {/* Plan Comparison */}
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
                
                {/* Usage Narrative */}
                <Paper elevation={0} sx={{ p: 2, mb: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                  <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                    {tier.name === 'FREE' && 'Great for testing and prototyping. Try our APIs, build a demo, experiment with standards. No credit card required.'}
                    {tier.name === 'STARTER' && 'For small teams shipping their first identity feature. Verify credentials for a single application or pilot project.'}
                    {tier.name === 'PROFESSIONAL' && 'For growing products with regular identity verification needs. Scale to thousands of verifications per month with full support.'}
                    {tier.name === 'ENTERPRISE' && 'For organizations running identity at scale. Unlimited usage, custom SLAs, dedicated support, and self-hosted options available.'}
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
                  The free tier includes 5 team members, 100 API calls/month, and 10 credentials/month. 
                  Perfect for development, testing, or small pilot projects.
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
                  All plans include unlimited access to documentation, SDKs, and community support. 
                  There are no limits on the number of credential types or trust registries you configure.
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
          Traditional IDV platforms charge per verification. ElevenID LLC provides infrastructure that 
          enables credential reuse, reducing long-term costs while increasing value.
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
