import { Box, Typography, Paper, Grid, Button, Divider } from '@mui/material';
import { SEOHead } from '../seo';
import { articleSchema, breadcrumbListSchema } from '../seo/structuredData';
import { useNavigate } from 'react-router-dom';
import BadgeIcon from '@mui/icons-material/Badge';

function WhatIsDigitalCredentialPage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="What Is a Digital Credential? — ElevenID"
        description="A digital credential is a machine-readable, cryptographically signed representation of a qualification, achievement, or identity attribute that can be independently verified."
        canonicalPath="/what-is-digital-credential"
        keywords={['digital credential', 'verifiable credential', 'electronic credential', 'digital certificate', 'credential types', 'credential formats']}
        structuredData={[
          articleSchema({
            headline: 'What Is a Digital Credential?',
            description: 'Understanding digital credentials: types, formats, lifecycle, and how they differ from traditional paper-based credentials.',
            datePublished: '2026-04-07',
            url: 'https://elevenidllc.com/what-is-digital-credential',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'What Is a Digital Credential?', url: 'https://elevenidllc.com/what-is-digital-credential' },
          ]),
          {
            '@context': 'https://schema.org',
            '@type': 'DefinedTerm',
            name: 'Digital Credential',
            description: 'A machine-readable, cryptographically signed representation of a qualification, achievement, or identity attribute.',
          },
        ]}
      />

      {/* Hero */}
      <Box sx={{
        textAlign: 'center', py: 6, mb: 6,
        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
        color: 'white', borderRadius: 2,
      }}>
        <BadgeIcon sx={{ fontSize: 56, mb: 2, opacity: 0.9 }} />
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          What Is a Digital Credential?
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          A machine-readable, cryptographically signed representation of a qualification, achievement,
          or identity attribute that can be independently verified.
        </Typography>
      </Box>

      {/* Definition */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Typography variant="h5" component="h2" gutterBottom fontWeight="bold">Definition</Typography>
        <Typography variant="body1" paragraph>
          A <strong>digital credential</strong> is the electronic equivalent of a physical document—a diploma,
          a license, an employee badge, a passport—represented as structured data with a cryptographic
          proof of authenticity. Unlike a scanned PDF or a database record, a digital credential is
          self-contained: it carries its own proof that it was issued by a specific authority and has not been modified.
        </Typography>
      </Paper>

      {/* Types */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Types of Digital Credentials
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { name: 'W3C Verifiable Credential', desc: 'A general-purpose credential format defined by the W3C, using JSON-LD and linked data proofs.', link: '/verifiable-credential-api' },
          { name: 'SD-JWT Credential', desc: 'A compact, privacy-preserving credential format that allows selective disclosure of claims.', link: '/sd-jwt-verification' },
          { name: 'ISO 18013-5 mDoc', desc: 'The standard for mobile documents like driving licenses and national eIDs, used in EUDI Wallets.', link: '/iso-18013-5-mdoc-verification' },
          { name: 'Open Badge', desc: 'An achievement credential designed for education and professional development contexts.', link: '/what-is-open-badge' },
        ].map((type) => (
          <Grid item xs={12} sm={6} key={type.name}>
            <Paper elevation={1} sx={{ p: 3, height: '100%', cursor: 'pointer' }} onClick={() => navigate(type.link)}>
              <Typography variant="h6" gutterBottom fontWeight="bold">{type.name}</Typography>
              <Typography variant="body2" color="text.secondary">{type.desc}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Lifecycle */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Credential Lifecycle
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { phase: 'Design', desc: 'Define credential schema, claims, and format using credential templates.' },
          { phase: 'Issue', desc: 'Create and sign the credential, delivering it to the holder\'s wallet.' },
          { phase: 'Hold', desc: 'The holder stores the credential and controls when and how it is shared.' },
          { phase: 'Present', desc: 'The holder presents the credential (or selected claims) to a verifier.' },
          { phase: 'Verify', desc: 'The verifier checks authenticity, validity, and trust.' },
          { phase: 'Revoke', desc: 'The issuer can revoke the credential if circumstances change.' },
        ].map((item, i) => (
          <Grid item xs={12} sm={6} md={4} key={item.phase}>
            <Paper elevation={0} sx={{ p: 2.5, border: '1px solid', borderColor: 'divider', borderRadius: 2, height: '100%' }}>
              <Typography variant="h6" color="primary.main" fontWeight="bold">{i + 1}. {item.phase}</Typography>
              <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* vs Physical */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Digital vs. Physical Credentials
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" fontWeight="bold" color="text.secondary" gutterBottom>Physical Credentials</Typography>
            <Typography variant="body2" color="text.secondary" component="ul" sx={{ pl: 2 }}>
              <li>Can be forged or altered</li>
              <li>Verification requires contacting the issuer</li>
              <li>Can be lost or damaged</li>
              <li>Shares all information at once</li>
              <li>Difficult to revoke after issuance</li>
            </Typography>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" fontWeight="bold" color="success.main" gutterBottom>Digital Credentials</Typography>
            <Typography variant="body2" color="text.secondary" component="ul" sx={{ pl: 2 }}>
              <li>Tamper-evident via cryptographic signatures</li>
              <li>Independently verifiable without issuer contact</li>
              <li>Backed up and recoverable</li>
              <li>Selective disclosure of specific claims</li>
              <li>Instantly revocable</li>
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      <Divider sx={{ my: 4 }} />

      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap', mb: 4 }}>
        <Button variant="contained" size="large" onClick={() => navigate('/product')}>
          Explore ElevenID
        </Button>
        <Button variant="outlined" size="large" onClick={() => navigate('/what-is-verifiable-identity')}>
          What Is Verifiable Identity?
        </Button>
      </Box>
    </Box>
  );
}

export default WhatIsDigitalCredentialPage;
