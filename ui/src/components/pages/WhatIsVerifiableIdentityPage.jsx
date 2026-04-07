import { Box, Typography, Paper, Grid, Button, Divider } from '@mui/material';
import { SEOHead } from '../seo';
import { articleSchema, breadcrumbListSchema } from '../seo/structuredData';
import { useNavigate } from 'react-router-dom';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

function WhatIsVerifiableIdentityPage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="What Is Verifiable Identity? — ElevenID"
        description="Verifiable identity is a system where identity claims are cryptographically signed by a trusted issuer, enabling third parties to verify them without contacting the issuer directly."
        canonicalPath="/what-is-verifiable-identity"
        keywords={['verifiable identity', 'digital identity', 'decentralized identity', 'verifiable credentials', 'identity verification', 'cryptographic identity']}
        structuredData={[
          articleSchema({
            headline: 'What Is Verifiable Identity?',
            description: 'A comprehensive explanation of verifiable identity: how it works, why it matters, and how ElevenID implements it.',
            datePublished: '2026-04-07',
            url: 'https://elevenidllc.com/what-is-verifiable-identity',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'What Is Verifiable Identity?', url: 'https://elevenidllc.com/what-is-verifiable-identity' },
          ]),
          {
            '@context': 'https://schema.org',
            '@type': 'DefinedTerm',
            name: 'Verifiable Identity',
            description: 'A system where identity claims are expressed as cryptographically signed credentials that third parties can verify without contacting the original issuer.',
            inDefinedTermSet: 'https://www.w3.org/TR/vc-data-model-2.0/',
          },
        ]}
      />

      {/* Hero */}
      <Box sx={{
        textAlign: 'center', py: 6, mb: 6,
        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
        color: 'white', borderRadius: 2,
      }}>
        <VerifiedUserIcon sx={{ fontSize: 56, mb: 2, opacity: 0.9 }} />
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          What Is Verifiable Identity?
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          A system where identity claims are cryptographically signed by a trusted issuer,
          enabling anyone to verify them independently.
        </Typography>
      </Box>

      {/* Definition */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Typography variant="h5" component="h2" gutterBottom fontWeight="bold">Definition</Typography>
        <Typography variant="body1" paragraph>
          <strong>Verifiable identity</strong> is a framework for representing identity information as
          cryptographically signed digital credentials. Unlike traditional identity checks—where a verifier
          must contact the issuing authority directly—verifiable credentials carry their own proof of
          authenticity, enabling instant, offline, and privacy-preserving verification.
        </Typography>
        <Typography variant="body1">
          The approach is defined by the <strong>W3C Verifiable Credentials Data Model</strong> and
          implemented through standards like OID4VCI, OID4VP, SD-JWT, and ISO 18013-5 (mDoc).
        </Typography>
      </Paper>

      {/* How It Works */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        How It Works
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {[
          { step: '1', title: 'Issuer Creates Credential', description: 'A trusted authority (university, employer, government) creates a digital credential containing identity claims and signs it with a cryptographic key.' },
          { step: '2', title: 'Holder Receives & Stores', description: 'The individual receives the credential in a digital wallet. They control when and how it is shared—no need for the issuer to be involved.' },
          { step: '3', title: 'Verifier Checks Credential', description: 'Any party can verify the credential by checking the cryptographic signature against the issuer\'s public key. No phone call, no API request to the issuer.' },
        ].map((item) => (
          <Grid item xs={12} md={4} key={item.step}>
            <Paper elevation={1} sx={{ p: 3, height: '100%' }}>
              <Typography variant="h4" color="primary.main" fontWeight="bold" gutterBottom>{item.step}</Typography>
              <Typography variant="h6" gutterBottom fontWeight="bold">{item.title}</Typography>
              <Typography variant="body2" color="text.secondary">{item.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Why traditional IDV fails */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Why Traditional Identity Verification Falls Short
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" fontWeight="bold" color="error.main" gutterBottom>Traditional IDV</Typography>
            <Typography variant="body2" color="text.secondary" component="ul" sx={{ pl: 2 }}>
              <li>Requires contacting the issuer for every check</li>
              <li>Creates centralized honeypots of personal data</li>
              <li>Shares more information than necessary</li>
              <li>Fails offline or across organizational boundaries</li>
              <li>Expensive per-verification costs</li>
            </Typography>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" fontWeight="bold" color="success.main" gutterBottom>Verifiable Identity</Typography>
            <Typography variant="body2" color="text.secondary" component="ul" sx={{ pl: 2 }}>
              <li>Verification is instant, independent, and offline-capable</li>
              <li>Data stays with the individual, not in centralized databases</li>
              <li>Selective disclosure reveals only what is needed</li>
              <li>Works across organizations, borders, and ecosystems</li>
              <li>Near-zero marginal cost per verification</li>
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* Example Credential */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Example: A Verifiable Credential
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 4, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "did:web:university.example",
  "issuanceDate": "2026-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mkh...",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Computer Science"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:university.example#key-1",
    "proofValue": "z58DAdFfa9Rr..."
  }
}`}
        </Box>
      </Paper>

      <Divider sx={{ my: 4 }} />

      {/* How ElevenID implements this */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        How ElevenID Implements Verifiable Identity
      </Typography>
      <Typography variant="body1" paragraph>
        ElevenID provides the complete infrastructure for organizations to issue, manage, and verify
        credentials across all major formats—W3C Verifiable Credentials, SD-JWT, ISO 18013-5 mDoc,
        and Open Badges.
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { label: 'Credential Templates', desc: 'Design what data gets issued and in which format' },
          { label: 'Trust Profiles', desc: 'Define who is trusted and under what rules' },
          { label: 'Presentation Policies', desc: 'Specify minimum disclosure requirements' },
          { label: 'Verification API', desc: 'Verify any credential format via a single endpoint' },
        ].map((item) => (
          <Grid item xs={12} sm={6} key={item.label}>
            <Paper elevation={0} sx={{ p: 2.5, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold">{item.label}</Typography>
              <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* CTA */}
      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap', mb: 4 }}>
        <Button variant="contained" size="large" onClick={() => navigate('/product')}>
          Explore the Platform
        </Button>
        <Button variant="outlined" size="large" onClick={() => navigate('/docs')}>
          API Documentation
        </Button>
      </Box>
    </Box>
  );
}

export default WhatIsVerifiableIdentityPage;
