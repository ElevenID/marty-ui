import { Box, Typography, Button, Grid, Card, CardContent } from '@mui/material';
import { useNavigate } from 'react-router';
import { SEOHead, softwareApplicationSchema } from '../seo';

function OpenBadgesVerificationPage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="Open Badges 3.0 Verification API"
        description="Evaluate an Open Badges workflow with a defined issuer, credential format, verification policy, and Marty release."
        canonicalPath="/open-badges-verification"
        structuredData={softwareApplicationSchema({ name: 'Open Badges Verification API', description: 'Open Badges 3.0 verification infrastructure.' })}
        keywords={['Open Badges 3.0 verification', 'Open Badges validator API', 'workforce credential verification']}
      />

      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>Open Badges 3.0 Verification API</Typography>
      <Typography variant="body1" sx={{ mb: 4 }}>
        Define the Open Badges version, proof format, issuer, and acceptance rules for your workforce or education workflow. Confirm the exact Marty release and executed interoperability evidence before use.
      </Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Workforce Evaluation</Typography><Typography variant="body2" color="text.secondary">Validate certifications, training completions, and skill badges.</Typography></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Education Evaluation</Typography><Typography variant="body2" color="text.secondary">Test digital diplomas and achievement credentials within the agreed scope.</Typography></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Policy Governed</Typography><Typography variant="body2" color="text.secondary">Control issuer trust and revocation checks centrally.</Typography></CardContent></Card></Grid>
      </Grid>

      <Button variant="contained" onClick={() => navigate('/open-badges-issuance')} sx={{ mr: 1 }}>Open Badges Issuance</Button>
      <Button variant="outlined" onClick={() => navigate('/docs')}>View API Docs</Button>
    </Box>
  );
}

export default OpenBadgesVerificationPage;
