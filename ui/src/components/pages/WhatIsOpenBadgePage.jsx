import { Box, Typography, Paper, Grid, Button, Divider } from '@mui/material';
import { SEOHead } from '../seo';
import { articleSchema, breadcrumbListSchema } from '../seo/structuredData';
import { useNavigate } from 'react-router-dom';
import EmojiEventsIcon from '@mui/icons-material/EmojiEvents';

function WhatIsOpenBadgePage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="What Is an Open Badge? — ElevenID"
        description="An Open Badge is a verifiable digital credential that represents an achievement, skill, or competency. Based on the Open Badges v3 standard, badges are portable, stackable, and machine-verifiable."
        canonicalPath="/what-is-open-badge"
        keywords={['Open Badge', 'digital badge', 'Open Badges v3', 'achievement credential', 'verifiable badge', 'micro-credential', 'digital credential']}
        structuredData={[
          articleSchema({
            headline: 'What Is an Open Badge?',
            description: 'A complete guide to Open Badges: what they are, how they work, and how to issue and verify them with ElevenID.',
            datePublished: '2026-04-07',
            url: 'https://elevenidllc.com/what-is-open-badge',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'What Is an Open Badge?', url: 'https://elevenidllc.com/what-is-open-badge' },
          ]),
          {
            '@context': 'https://schema.org',
            '@type': 'DefinedTerm',
            name: 'Open Badge',
            description: 'A verifiable digital credential conforming to the Open Badges v3.0 standard that represents a skill, competency, or achievement.',
          },
        ]}
      />

      {/* Hero */}
      <Box sx={{
        textAlign: 'center', py: 6, mb: 6,
        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
        color: 'white', borderRadius: 2,
      }}>
        <EmojiEventsIcon sx={{ fontSize: 56, mb: 2, opacity: 0.9 }} />
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          What Is an Open Badge?
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          A verifiable digital credential that represents an achievement, skill, or competency—portable,
          stackable, and machine-verifiable.
        </Typography>
      </Box>

      {/* Definition */}
      <Paper elevation={0} sx={{ p: 4, mb: 4, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
        <Typography variant="h5" component="h2" gutterBottom fontWeight="bold">Definition</Typography>
        <Typography variant="body1" paragraph>
          An <strong>Open Badge</strong> is a digital credential conforming to the <strong>Open Badges v3.0 standard</strong> (an
          IMS Global / 1EdTech specification). It packages a claim about an achievement—a course
          completion, a certification, a skill—into a verifiable, portable format that the recipient
          owns and can share anywhere.
        </Typography>
        <Typography variant="body1">
          Open Badges v3 aligns with the W3C Verifiable Credentials Data Model, meaning they carry
          cryptographic proofs and can be verified independently.
        </Typography>
      </Paper>

      {/* How it works */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        How Open Badges Work
      </Typography>
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {[
          { step: '1', title: 'Achievement Defined', description: 'An organization defines the criteria for an achievement—completing a course, passing an exam, earning a certification.' },
          { step: '2', title: 'Badge Issued', description: 'When a learner meets the criteria, the organization issues an Open Badge containing the achievement details, signed cryptographically.' },
          { step: '3', title: 'Badge Shared', description: 'The recipient stores the badge in a digital wallet and can share it with employers, platforms, or other institutions.' },
          { step: '4', title: 'Badge Verified', description: 'Any recipient of the shared badge can verify its authenticity and check whether the issuer is trusted.' },
        ].map((item) => (
          <Grid item xs={12} sm={6} key={item.step}>
            <Paper elevation={1} sx={{ p: 3, height: '100%' }}>
              <Typography variant="h4" color="primary.main" fontWeight="bold" gutterBottom>{item.step}</Typography>
              <Typography variant="h6" gutterBottom fontWeight="bold">{item.title}</Typography>
              <Typography variant="body2" color="text.secondary">{item.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Example */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Example: An Open Badge Credential
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 4, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
  ],
  "type": ["VerifiableCredential", "OpenBadgeCredential"],
  "issuer": {
    "id": "did:web:academy.example",
    "name": "Academy Example"
  },
  "issuanceDate": "2026-03-01T00:00:00Z",
  "credentialSubject": {
    "type": "AchievementSubject",
    "achievement": {
      "type": "Achievement",
      "name": "Cloud Security Fundamentals",
      "description": "Demonstrated proficiency in cloud security principles.",
      "criteria": {
        "narrative": "Complete all modules and pass the final assessment with 80%+."
      }
    }
  }
}`}
        </Box>
      </Paper>

      {/* Use cases */}
      <Typography variant="h5" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Where Open Badges Are Used
      </Typography>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        {[
          { title: 'Higher Education', desc: 'Universities issue verifiable degree and course completion badges.' },
          { title: 'Professional Training', desc: 'Certification bodies issue badges for professional qualifications.' },
          { title: 'Corporate Learning', desc: 'Companies recognize internal training and skill development.' },
          { title: 'Workforce Development', desc: 'Government programs issue badges for workforce readiness.' },
        ].map((uc) => (
          <Grid item xs={12} sm={6} key={uc.title}>
            <Paper elevation={0} sx={{ p: 2.5, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold">{uc.title}</Typography>
              <Typography variant="body2" color="text.secondary">{uc.desc}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      <Divider sx={{ my: 4 }} />

      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap', mb: 4 }}>
        <Button variant="contained" size="large" onClick={() => navigate('/open-badges-issuance')}>
          Issue Open Badges
        </Button>
        <Button variant="outlined" size="large" onClick={() => navigate('/open-badges-verification')}>
          Verify Open Badges
        </Button>
      </Box>
    </Box>
  );
}

export default WhatIsOpenBadgePage;
