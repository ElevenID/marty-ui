import { Box, Typography, Paper, Grid, Button, Divider } from '@mui/material';
import { SEOHead } from '../seo';
import { articleSchema, breadcrumbListSchema } from '../seo/structuredData';
import { useNavigate } from 'react-router-dom';
import SearchIcon from '@mui/icons-material/Search';

function WhatIsCredentialVerificationPage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="What Is Credential Verification? — ElevenID"
        description="Credential verification is the process of cryptographically validating that a digital credential is authentic, unrevoked, and issued by a trusted authority."
        canonicalPath="/what-is-credential-verification"
        keywords={['credential verification', 'verifiable credential verification', 'digital credential validation', 'cryptographic verification', 'trust verification']}
        structuredData={[
          articleSchema({
            headline: 'What Is Credential Verification?',
            description: 'How credential verification works: signature validation, revocation checks, trust evaluation, and how ElevenID automates it.',
            datePublished: '2026-04-07',
            url: 'https://elevenidllc.com/what-is-credential-verification',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'What Is Credential Verification?', url: 'https://elevenidllc.com/what-is-credential-verification' },
          ]),
          {
            '@context': 'https://schema.org',
            '@type': 'DefinedTerm',
            name: 'Credential Verification',
            description: 'The process of cryptographically validating that a digital credential is authentic, has not been revoked, and was issued by a trusted authority.',
          },
        ]}
      />

      {/* Hero */}
      <Box sx={{
        textAlign: 'center', py: 6, mb: 6,
        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
        color: 'white', borderRadius: 2,
      }}>
        <SearchIcon sx={{ fontSize: 56, mb: 2, opacity: 0.9 }} />
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          What Is Credential Verification?
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          The process of cryptographically confirming that a digital credential is authentic,
          unrevoked, and issued by a trusted authority—without contacting the issuer.
        </Typography>
      </Box>

      {/* Definition */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Typography variant="h5" component="h2" gutterBottom fontWeight="bold">Definition</Typography>
        <Typography variant="body1" paragraph>
          <strong>Credential verification</strong> is the act of validating that a digital credential
          presented by a holder is genuine, has not been tampered with, has not been revoked, and was
          issued by an authority the verifier trusts. It involves checking cryptographic signatures,
          evaluating trust chains, and applying business rules—all without requiring real-time
          communication with the credential issuer.
        </Typography>
      </Paper>

      {/* Verification Steps */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        How Verification Works
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { step: '1', title: 'Signature Check', description: 'The verifier checks the cryptographic signature on the credential against the issuer\'s public key to ensure it has not been altered.' },
          { step: '2', title: 'Expiration Check', description: 'The credential\'s validity period is evaluated to confirm it has not expired.' },
          { step: '3', title: 'Revocation Check', description: 'The verifier checks a revocation list or status endpoint to confirm the credential has not been withdrawn by the issuer.' },
          { step: '4', title: 'Issuer Trust Evaluation', description: 'The issuer\'s DID or public key is checked against a trust registry to confirm they are authorized to issue the credential type.' },
          { step: '5', title: 'Policy Evaluation', description: 'Custom business rules—minimum disclosure, holder binding, compliance requirements—are applied to the credential presentation.' },
        ].map((item) => (
          <Grid item xs={12} key={item.step}>
            <Paper elevation={0} sx={{ p: 2.5, border: '1px solid', borderColor: 'divider', borderRadius: 2, display: 'flex', gap: 2 }}>
              <Typography variant="h5" color="primary.main" fontWeight="bold" sx={{ minWidth: 32 }}>{item.step}</Typography>
              <Box>
                <Typography variant="subtitle1" fontWeight="bold">{item.title}</Typography>
                <Typography variant="body2" color="text.secondary">{item.description}</Typography>
              </Box>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Supported Formats */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Credential Formats Supported
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { name: 'W3C Verifiable Credentials', desc: 'JSON-LD credentials with linked data proofs', link: '/verifiable-credential-api' },
          { name: 'SD-JWT', desc: 'Selective Disclosure JSON Web Tokens for privacy-preserving presentation', link: '/sd-jwt-verification' },
          { name: 'ISO 18013-5 mDoc', desc: 'Mobile document format used by mobile driving licenses and national eIDs', link: '/iso-18013-5-mdoc-verification' },
          { name: 'Open Badges v3', desc: 'Achievement credentials for education and professional development', link: '/open-badges-verification' },
        ].map((fmt) => (
          <Grid item xs={12} sm={6} key={fmt.name}>
            <Paper elevation={1} sx={{ p: 2.5, height: '100%', cursor: 'pointer' }} onClick={() => navigate(fmt.link)}>
              <Typography variant="subtitle1" fontWeight="bold">{fmt.name}</Typography>
              <Typography variant="body2" color="text.secondary">{fmt.desc}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* API Example */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Verification API Example
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 2, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Request</Typography>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`POST /api/v1/flows/verify
Content-Type: application/json

{
  "organization_id": "org_123",
  "presentation_policy_id": "policy_123",
  "external_reference": "Employment eligibility check"
}`}
        </Box>
      </Paper>
      <Paper elevation={0} sx={{ p: 3, mb: 4, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Response</Typography>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`{
  "instance_id": "flow_123",
  "status": "AWAITING_WALLET",
  "request_uri": "openid4vp://...",
  "qr_code_data": "..."
}`}
        </Box>
      </Paper>

      <Divider sx={{ my: 4 }} />

      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap', mb: 4 }}>
        <Button variant="contained" size="large" onClick={() => navigate('/verifiable-credential-api')}>
          Verification API
        </Button>
        <Button variant="outlined" size="large" onClick={() => navigate('/docs')}>
          Full Documentation
        </Button>
      </Box>
    </Box>
  );
}

export default WhatIsCredentialVerificationPage;
