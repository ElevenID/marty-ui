import { Box, Typography, Button, Grid, Card, CardContent } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { SEOHead, softwareApplicationSchema } from '../seo';

function OpenBadgesVerificationPage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="Open Badges 3.0 Verification API"
        description="Verify Open Badges 3.0 with W3C Verifiable Credentials, cryptographic proofs, issuer trust checks, and revocation validation."
        canonicalPath="/open-badges-verification"
        structuredData={softwareApplicationSchema({ name: 'Open Badges Verification API', description: 'Open Badges 3.0 verification infrastructure.' })}
        keywords={['Open Badges 3.0 verification', 'Open Badges validator API', 'workforce credential verification']}
      />

      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>Open Badges 3.0 Verification API</Typography>
      <Typography variant="body1" sx={{ mb: 4 }}>
        Verify workforce and education credentials as W3C Verifiable Credentials with centralized trust governance and standards-compliant proof validation.
      </Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Workforce Ready</Typography><Typography variant="body2" color="text.secondary">Validate certifications, training completions, and skill badges.</Typography></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Education Ready</Typography><Typography variant="body2" color="text.secondary">Verify digital diplomas and achievement credentials at scale.</Typography></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Policy Governed</Typography><Typography variant="body2" color="text.secondary">Control issuer trust and revocation checks centrally.</Typography></CardContent></Card></Grid>
      </Grid>

      <Button variant="contained" onClick={() => navigate('/open-badges-issuance')} sx={{ mr: 1 }}>Open Badges Issuance</Button>
      <Button variant="outlined" onClick={() => navigate('/docs')}>View API Docs</Button>
    </Box>
  );
}

export default OpenBadgesVerificationPage;
