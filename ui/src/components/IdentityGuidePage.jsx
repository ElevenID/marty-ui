/**
 * Identity Guide Page
 * 
 * Educational content explaining how digital identity works
 * Adapted from Digital_Identity_model.md and White_Paper.md
 */

import { Box, Typography, Paper, Card, CardContent, Grid, List, ListItem, ListItemText, Divider, Chip } from '@mui/material';
import { SEOHead } from './seo';
import { articleSchema, breadcrumbListSchema } from './seo/structuredData';
import { IDENTITY_CONCEPTS } from '../data/marketingContent';
import { TrustModelDiagram, IdentityTransactionDiagram, CredentialFlowDiagram } from './diagrams';
import Button from '@mui/material/Button';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useNavigate } from 'react-router-dom';

function IdentityGuidePage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="How Digital Identity Works"
        description="Technical guide to digital identity trust models, issuer-holder-verifier flows, and standards-based verifiable credential architecture."
        canonicalPath="/identity"
        keywords={['digital identity', 'verifiable credentials', 'issuer holder verifier model', 'identity trust architecture']}
        structuredData={[
          articleSchema({
            headline: 'How Digital Identity Works',
            description: 'Technical guide to digital identity trust models, issuer-holder-verifier flows, and standards-based verifiable credential architecture.',
            datePublished: '2024-01-01',
            url: 'https://elevenidllc.com/identity',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'How Digital Identity Works', url: 'https://elevenidllc.com/identity' },
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
          How Digital Identity Works
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          Understanding identity as trust, policy, and flow
        </Typography>
      </Box>
      {/* TL;DR - 60 Second Summary */}
      <Paper 
        elevation={3} 
        sx={{ 
          p: 4, 
          mb: 6, 
          bgcolor: 'primary.light', 
          color: 'primary.contrastText',
          borderRadius: 2
        }}
      >
        <Typography variant="h5" fontWeight="bold" gutterBottom>
          TL;DR: Identity in 60 Seconds
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.7 }}>
          Digital identity isn&apos;t about who you are—it&apos;s about <strong>who trusts you for what</strong>.
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.7 }}>
          Every transaction answers: <strong>Who says?</strong> (Issuer) → <strong>Says what?</strong> (Claims) → <strong>Who checks?</strong> (Verifier).
          An Issuer creates credentials; a Holder stores them; a Verifier checks them; Trust Registries govern which issuers to trust.
        </Typography>
        <Typography variant="body1" sx={{ fontSize: '1.05rem', fontStyle: 'italic' }}>
          Below: standards, protocols, and implementation.
        </Typography>
      </Paper>
      {/* What Identity Is */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          {IDENTITY_CONCEPTS.whatIs.title}
        </Typography>
        <Typography variant="h6" color="text.secondary" gutterBottom sx={{ fontStyle: 'italic' }}>
          {IDENTITY_CONCEPTS.whatIs.tagline}
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.1rem', lineHeight: 1.8 }}>
          {IDENTITY_CONCEPTS.whatIs.definition}
        </Typography>

        <Paper elevation={2} sx={{ p: 4, bgcolor: 'warning.light', color: 'warning.contrastText', my: 4 }}>
          <Typography variant="h6" fontWeight="bold" gutterBottom>
            Why Traditional Identity Systems Fail
          </Typography>
          <List>
            {IDENTITY_CONCEPTS.whatIs.problems.map((problem) => (
              <ListItem key={problem} sx={{ py: 0.5 }}>
                <ListItemText primary={problem} />
              </ListItem>
            ))}
          </List>
        </Paper>
      </Box>
      <Divider sx={{ my: 8 }} />
      {/* Three Questions */}
      <Box sx={{ mb: 8 }}>
        <Paper elevation={2} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <IdentityTransactionDiagram interactive={true} />
        </Paper>

        <Box sx={{ mt: 4 }}>
          <Typography variant="body1" paragraph>
            {IDENTITY_CONCEPTS.threeQuestions.conclusion}
          </Typography>

          <Grid container spacing={3} sx={{ mt: 2 }}>
            {IDENTITY_CONCEPTS.threeQuestions.questions.map((item) => (
              <Grid item xs={12} md={4} key={item.question}>
                <Card elevation={2}>
                  <CardContent>
                    <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
                      {item.question}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {item.description}
                    </Typography>
                    <Typography variant="body2">
                      {item.detail}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      </Box>
      <Divider sx={{ my: 8 }} />
      {/* Four Primitives */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {IDENTITY_CONCEPTS.fourPrimitives.title}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph>
          {IDENTITY_CONCEPTS.fourPrimitives.tagline}
        </Typography>
        <Typography variant="body2" color="primary.main" textAlign="center" paragraph sx={{ mb: 6, fontWeight: 500 }}>
          Policies are configuration, not code. Endpoints execute centrally governed trust and disclosure rules without redeployment.
        </Typography>

        <Paper elevation={2} sx={{ p: 4, bgcolor: 'grey.50', mb: 6 }}>
          <TrustModelDiagram interactive={true} />
        </Paper>

        <Grid container spacing={4}>
          {IDENTITY_CONCEPTS.fourPrimitives.primitives.map((primitive) => (
            <Grid item xs={12} md={6} key={primitive.name}>
              <Card elevation={3} sx={{ height: '100%' }}>
                <CardContent>
                  <Typography variant="h5" fontWeight="bold" color="primary" gutterBottom>
                    {primitive.name}
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" paragraph sx={{ fontStyle: 'italic' }}>
                    {primitive.purpose}
                  </Typography>

                  <Typography variant="subtitle2" fontWeight="bold" gutterBottom sx={{ mt: 2 }}>
                    Contains:
                  </Typography>
                  <List dense>
                    {primitive.contains.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5 }}>
                        <ListItemText 
                          primary={item}
                          slotProps={{
                            primary: { variant: 'body2' }
                          }}
                        />
                      </ListItem>
                    ))}
                  </List>

                  <Box sx={{ mt: 2 }}>
                    <Chip 
                      label={primitive.stability} 
                      size="small" 
                      variant="outlined"
                      color="secondary"
                    />
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>
      <Divider sx={{ my: 8 }} />
      {/* Flows */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center">
          {IDENTITY_CONCEPTS.flows.title}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" paragraph sx={{ mb: 4 }}>
          {IDENTITY_CONCEPTS.flows.description}
        </Typography>

        <Paper elevation={2} sx={{ p: 4, bgcolor: 'grey.50', mb: 6 }}>
          <CredentialFlowDiagram interactive={true} />
        </Paper>

        <Typography variant="h5" fontWeight="bold" gutterBottom>
          Real-World Flow Examples
        </Typography>

        <Grid container spacing={3}>
          {IDENTITY_CONCEPTS.flows.examples.map((example) => (
            <Grid item xs={12} md={4} key={example.name}>
              <Card elevation={2}>
                <CardContent>
                  <Typography variant="h6" fontWeight="bold" gutterBottom>
                    {example.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {example.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>
      {/* Summary CTA */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          bgcolor: 'primary.main',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Identity as Infrastructure
        </Typography>
        <Typography variant="body1" sx={{ maxWidth: 800, mx: 'auto', mb: 2 }}>
          Digital identity becomes automatable when modeled as trust configuration, credential templates, 
          presentation policies, and deployment profiles—orchestrated by flows that handle the complete 
          lifecycle from application through verification.
        </Typography>
        <Typography variant="body2" sx={{ maxWidth: 700, mx: 'auto', mb: 3, opacity: 0.85 }}>
          These primitives are now formalized in the <strong>Marty Identity Protocol (MIP)</strong>—an 
          open, vendor-neutral specification.
        </Typography>
        <Button
          variant="outlined"
          size="large"
          onClick={() => navigate('/protocol')}
          endIcon={<ArrowForwardIcon />}
          sx={{ color: 'white', borderColor: 'white', '&:hover': { borderColor: 'white', bgcolor: 'rgba(255,255,255,0.1)' } }}
        >
          Explore the Open Protocol
        </Button>
      </Box>
    </Box>
  );
}

export default IdentityGuidePage;
