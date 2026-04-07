import { Box, Typography, Paper, Grid, Button, Divider, Chip } from '@mui/material';
import { SEOHead } from '../seo';
import { breadcrumbListSchema, protocolSchema } from '../seo/structuredData';
import { useNavigate } from 'react-router-dom';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

const primitives = [
  { name: 'Trust Profile', desc: 'Defines who is trusted, under what rules, and for which credential types.' },
  { name: 'Credential Template', desc: 'Specifies the schema, format, and claims for issued credentials.' },
  { name: 'Presentation Policy', desc: 'Declares what must be disclosed and what can be withheld during verification.' },
  { name: 'Deployment Profile', desc: 'Configures how credential infrastructure is deployed in a specific environment.' },
  { name: 'Flow', desc: 'Orchestrates the multi-step lifecycle of credential issuance, presentation, and verification.' },
  { name: 'Compliance Profile', desc: 'Bridges regulatory requirements to technical policy enforcement.' },
];

function WhatIsMartyProtocolPage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="What Is the Marty Identity Protocol (MIP)? — ElevenID"
        description="The Marty Identity Protocol (MIP) is an open standard defining the minimum set of primitives for issuing, holding, presenting, and verifying digital credentials under explicit rules of trust."
        canonicalPath="/what-is-marty-protocol"
        keywords={['Marty Identity Protocol', 'MIP', 'identity protocol', 'credential protocol', 'trust framework', 'open standard identity', 'verifiable credential standard']}
        structuredData={[
          protocolSchema(),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'What Is the Marty Identity Protocol?', url: 'https://elevenidllc.com/what-is-marty-protocol' },
          ]),
          {
            '@context': 'https://schema.org',
            '@type': 'DefinedTerm',
            name: 'Marty Identity Protocol',
            description: 'An open standard defining the minimum automatable set of primitives required for issuing, holding, presenting, and verifying digital credentials under explicit rules of trust and disclosure.',
          },
        ]}
      />

      {/* Hero */}
      <Box sx={{
        textAlign: 'center', py: 6, mb: 6,
        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
        color: 'white', borderRadius: 2,
      }}>
        <AccountTreeIcon sx={{ fontSize: 56, mb: 2, opacity: 0.9 }} />
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          What Is the Marty Identity Protocol?
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          An open standard defining the minimum set of primitives for issuing, holding,
          presenting, and verifying digital credentials under explicit rules of trust.
        </Typography>
      </Box>

      {/* Definition */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Typography variant="h5" component="h2" gutterBottom fontWeight="bold">Definition</Typography>
        <Typography variant="body1" paragraph>
          The <strong>Marty Identity Protocol (MIP)</strong> is an open specification that defines
          the core building blocks—called <em>primitives</em>—needed to manage digital credentials
          across their entire lifecycle. It addresses the gap between existing credential format
          standards (like W3C VC, SD-JWT, mDoc) and the operational requirements of real-world
          identity systems: trust governance, policy enforcement, deployment configuration, and
          compliance automation.
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Chip label="Open Source" size="small" color="primary" variant="outlined" />
          <Chip label="Apache 2.0" size="small" variant="outlined" />
          <Chip label="Format Agnostic" size="small" variant="outlined" />
          <Chip label="v0.1.0" size="small" variant="outlined" />
        </Box>
      </Paper>

      {/* Primitives */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Protocol Primitives
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {primitives.map((prim) => (
          <Grid item xs={12} sm={6} key={prim.name}>
            <Paper elevation={0} sx={{ p: 2.5, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold">{prim.name}</Typography>
              <Typography variant="body2" color="text.secondary">{prim.desc}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* What MIP solves */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        What Problem Does MIP Solve?
      </Typography>
      <Paper elevation={0} sx={{ p: 4, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Typography variant="body1" paragraph>
          Existing credential standards tell you <em>what format</em> to use (JSON-LD, SD-JWT, mDoc)
          and <em>how to exchange</em> them (OID4VCI, OID4VP). But they don't answer:
        </Typography>
        <Typography variant="body1" component="ul" sx={{ pl: 2, mb: 2 }}>
          <li>Who decides which issuers are trusted?</li>
          <li>What policies govern what can be disclosed?</li>
          <li>How do you configure a deployment for a specific regulation?</li>
          <li>How do you orchestrate multi-step identity workflows?</li>
        </Typography>
        <Typography variant="body1">
          MIP defines the operational layer that sits above format and exchange standards,
          providing a consistent model for trust, policy, deployment, and compliance.
        </Typography>
      </Paper>

      {/* Example */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Example: A Trust Profile
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 4, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`{
  "id": "trust-profile-eudi-pid",
  "name": "EUDI PID Verification",
  "version": "1.0.0",
  "trustFramework": "eIDAS2",
  "acceptedFormats": ["sd-jwt", "mdoc"],
  "trustedIssuers": [
    { "did": "did:web:gov.example", "credentialTypes": ["PersonIdentificationData"] }
  ],
  "policies": {
    "minimumDisclosure": true,
    "holderBinding": "required",
    "revocationCheck": "mandatory"
  }
}`}
        </Box>
      </Paper>

      <Divider sx={{ my: 4 }} />

      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap', mb: 4 }}>
        <Button variant="contained" size="large" onClick={() => navigate('/protocol')}>
          Full Protocol Specification
        </Button>
        <Button variant="outlined" size="large" onClick={() => navigate('/blog/introducing-mip')}>
          Read the MIP Introduction
        </Button>
      </Box>
    </Box>
  );
}

export default WhatIsMartyProtocolPage;
