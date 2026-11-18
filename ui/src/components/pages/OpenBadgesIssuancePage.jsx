import { useSurfaceNavigate } from '../../application/routing/useSurfaceNavigate';
import { Alert, Box, Typography, Button, Stack } from '@mui/material';

import { SEOHead, softwareApplicationSchema } from '../seo';

function OpenBadgesIssuancePage() {
  const navigate = useSurfaceNavigate();
  return (
    <Box>
      <SEOHead
        title="Open Badges 3.0 Issuance API"
        description="Evaluate an Open Badges issuance workflow with a defined credential template, issuer, recipient wallet, and Marty release."
        canonicalPath="/open-badges-issuance"
        structuredData={softwareApplicationSchema({ name: 'Open Badges Issuance API', description: 'Open Badges 3.0 issuance and lifecycle infrastructure.' })}
        keywords={['Open Badges issuance API', 'W3C VC issuance', 'education credential issuance']}
      />
      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>Open Badges 3.0 Issuance Infrastructure</Typography>
      <Typography variant="body1" sx={{ mb: 3 }}>
        Define the badge version, credential template, issuer, lifecycle, and recipient wallet. Validate the specific release and interoperability evidence using synthetic data before issuing real credentials.
      </Typography>
      <Alert severity="info" sx={{ mb: 3 }}>
        Sign in to an organization to set up a badge workflow. You will need an active issuer,
        compatible trust and compliance profiles, and an issuance flow. Start with synthetic learner data.
      </Alert>
      <Typography variant="h5" component="h2" sx={{ mb: 1 }}>Walk through the badge journey</Typography>
      <Box component="ol" sx={{ pl: 3, mb: 3 }}>
        <li><Typography><strong>Issuer:</strong> choose Open Badge Credential in the template builder, then use the Open Badges achievement starter. Configure the criteria and approval workflow.</Typography></li>
        <li><Typography><strong>Learner:</strong> apply, receive approval, and claim the badge through a compatible wallet.</Typography></li>
        <li><Typography><strong>Verifier:</strong> verify the issued badge and check its current lifecycle status.</Typography></li>
      </Box>
      <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', mb: 2 }}>
        <Button variant="contained" onClick={() => navigate('/console/org/templates/credentials/new')}>Set up a badge workflow</Button>
        <Button variant="outlined" onClick={() => navigate('/demos')}>Review demo evidence</Button>
        <Button variant="outlined" onClick={() => navigate('/docs')}>View API Docs</Button>
        <Button variant="outlined" onClick={() => navigate('/open-badges-verification')}>Open Badges Verification</Button>
      </Stack>
      <Typography variant="body2" color="text.secondary">
        Demo evidence records which scenarios have been run and their limitations. Check that evidence separately from your own deployment's results.
      </Typography>
    </Box>
  );
}

export default OpenBadgesIssuancePage;
