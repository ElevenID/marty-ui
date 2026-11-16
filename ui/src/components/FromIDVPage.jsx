import { useSurfaceNavigate } from '../application/routing/useSurfaceNavigate';
/**
 * From IDV to Verifiable Identity Page
 * 
 * Workflow guide for evaluating credential reuse, customer operation, and
 * release-specific trust and acceptance requirements
 */

import { Box, Typography, Paper, Card, CardContent, Grid, List, ListItem, ListItemIcon, ListItemText, Divider, Button } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { SHOW_PUBLIC_CTA } from '@ui-public-config';
import { SEOHead } from './seo';
import { articleSchema, breadcrumbListSchema } from './seo/structuredData';
import { useBranding } from '../hooks/useBranding';

function FromIDVPage() {
  const navigate = useSurfaceNavigate();
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
    'Define the credential format, issuer, wallet, and presentation profile for the selected workflow',
    'Test credential reuse under each verifier’s trust, freshness, and acceptance rules',
    'Configure issuer trust and policy decisions in the customer-operated environment',
    'Validate the selected disclosure mechanism with synthetic data and applicable rejected cases',
  ];

  const audiences = [
    {
      title: 'Governments',
      urgency: 'Review the credential profiles, acceptance requirements, and operator for the proposed workflow.',
      points: [
        'Profile-specific wallet evaluation',
        'Applicable acceptance and procurement requirements',
      ],
    },
    {
      title: 'Enterprises',
      urgency: 'Identify where credential reuse could improve a defined workflow.',
      points: [
        'Evidence for the selected workflow',
        'Named customer or partner operator',
      ],
    },
    {
      title: 'Platforms & Issuers',
      urgency: 'Define the achievement or document check your users need.',
      points: [
        'Workforce and education credentials',
        'Defined component and distribution rights',
      ],
    },
    {
      title: 'Developers',
      urgency: 'Review documented interfaces and test the exact release and integration.',
      points: [
        'Documented APIs and release scope',
        'Customer or selected-partner operation',
      ],
    },
  ];

  return (
    <Box>
      <SEOHead
        title="Why Verifiable Identity"
        description="Evaluate credential reuse within a defined customer-operated Marty workflow, with release-specific trust, interoperability, and acceptance evidence."
        canonicalPath="/why-verifiable-identity"
        keywords={['identity verification', 'verifiable identity', 'IDV modernization', 'reusable trust infrastructure']}
        structuredData={[
          articleSchema({
            headline: 'Why Verifiable Identity',
            description: 'Evaluate credential reuse within a defined customer-operated Marty workflow, with release-specific trust, interoperability, and acceptance evidence.',
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
          Plan a Verifiable Identity Workflow
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 900, mx: 'auto', opacity: 0.95, mb: 2 }}>
          Credential reuse starts with a defined claim, a trusted issuer, and a verifier&apos;s{' '}
          <strong>acceptance and disclosure requirements</strong>.
        </Typography>
        <Typography variant="body1" sx={{ maxWidth: 900, mx: 'auto', opacity: 0.9 }}>
          Marty is one customer-operated product for <strong>education and workforce credentials,
          applicant and document verification, and Travel Trust</strong>. Each use case has its own
          evidence requirements; a result in one does not qualify the others.
        </Typography>
      </Box>
      {/* Section 1 - The IDV Plateau */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Start with the decision your workflow must make
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
          Identify the claim or document check, the evidence needed, and the party responsible for the decision.
          Assess each available implementation against those requirements; capabilities and operating models vary.
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, fontWeight: 500 }}>
          A reusable credential may support more than one workflow when each verifier accepts its issuer,
          format, holder-binding mechanism, and current status.
        </Typography>
      </Box>
      <Divider sx={{ my: 8 }} />
      {/* Section 2 - What Changed */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Review wallets, formats, and acceptance requirements together
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
          Names such as W3C Verifiable Credentials, ISO 18013-5, and EUDI Wallet identify areas to evaluate.
          Confirm the exact specification, wallet build, presentation profile, and Marty release. The responsible
          organization must review applicable acceptance requirements; a standard name is not regulatory approval.
        </Typography>
        <Paper elevation={2} sx={{ p: 3, mt: 3, bgcolor: 'primary.light', color: 'primary.contrastText' }}>
          <Typography variant="h6" textAlign="center">
            Record the <strong>tested scope, trust decisions, and known limitations</strong> for each workflow.
          </Typography>
        </Paper>
      </Box>
      <Divider sx={{ my: 8 }} />
      {/* Section 3 - The Missing Layer in Most IDV Platforms */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Make Trust Responsibilities Explicit
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom sx={{ mb: 4 }}>
          Define the evidence and policy behind each decision
        </Typography>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
          Distinguish the questions your workflow asks:
        </Typography>
        <List>
          {['Which document checks are demonstrated?', 'How is the presenter bound to the evidence?', 'Which trust and acceptance rules apply?'].map((item, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <CheckCircleIcon color="action" />
              </ListItemIcon>
              <ListItemText primary={item} />
            </ListItem>
          ))}
        </List>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mt: 3 }}>
          Keep <strong>structural checks, cryptographic authenticity, and holder binding</strong> distinct.
          A passing check in one category does not prove the others.
        </Typography>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mb: 3 }}>
          Use these configuration concepts to describe the selected workflow:
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
          Connect these concepts through a defined <strong>flow</strong>. Validate its documented interfaces,
          selected devices, connectivity requirements, and rejected cases against the exact release.
        </Typography>

        <Paper elevation={2} sx={{ p: 3, mt: 3, bgcolor: 'grey.100', borderRadius: 2 }}>
          <Typography variant="body1" sx={{ fontSize: '1.05rem', lineHeight: 1.8 }}>
            <strong>Production operation belongs to your organization or selected partner.</strong>{' '}
            Agree who installs, monitors, backs up, and maintains the environment. The software offer does not
            include managed production or guaranteed technical support.
          </Typography>
        </Paper>
      </Box>
      <Divider sx={{ my: 8 }} />
      {/* Section 4 - How ElevenID LLC Solves Identity Management */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Evaluate Marty by {branding.branding.appName}
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom sx={{ mb: 4 }}>
          Select one useful workflow and its evidence requirements
        </Typography>

        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.8, mb: 3 }}>
          Use the release documentation and executed tests to evaluate the scope your organization needs:
        </Typography>

        <List>
          {implementations.map((item, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <CheckCircleIcon color="success" />
              </ListItemIcon>
              <ListItemText 
                primary={item}
                slotProps={{
                  primary: { fontSize: '1.05rem' }
                }}
              />
            </ListItem>
          ))}
        </List>

        <Paper elevation={2} sx={{ p: 4, mt: 4, bgcolor: 'success.light', color: 'success.contrastText' }}>
          <Typography variant="h6" textAlign="center" fontWeight="bold">
            Begin with <strong>synthetic data and a bounded workflow</strong>. Real records require accepted
            customer evaluation and the required security/privacy approvals; production additionally requires
            applicable signed terms and explicit authorization.
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
          Identify the workflow owner, operating team, and acceptance requirements
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
                          slotProps={{
                            primary: { variant: 'body2' }
                          }}
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
          What the Evaluation Should Establish
        </Typography>
        <Typography variant="h6" color="text.secondary" textAlign="center" gutterBottom sx={{ mb: 4 }}>
          A recorded result for the exact release, inputs, and operating environment
        </Typography>

        <Paper elevation={3} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <Typography variant="h5" sx={{ textAlign: 'center', fontWeight: 'bold', color: 'primary.main', my: 2 }}>
            Demonstrate the agreed workflow and its failure cases. Record what remains unproved before expanding scope.
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
          Define your next evaluation
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4, maxWidth: 600, mx: 'auto' }}>
          Review the relevant demonstration and documentation, then discuss a bounded annual software license.
          Price, included scope, component rights, and delivery terms require an agreed offer.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          {SHOW_PUBLIC_CTA && <Button
            variant="contained"
            size="large"
            onClick={() => navigate('/developers')}
            endIcon={<ArrowForwardIcon />}
            sx={{ px: 4 }}
          >
            Explore Developer Docs
          </Button>}
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
