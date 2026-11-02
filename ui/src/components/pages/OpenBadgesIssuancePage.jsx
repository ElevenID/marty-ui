import { Box, Typography, Button } from '@mui/material';
import { useNavigate } from 'react-router';
import { SEOHead, softwareApplicationSchema } from '../seo';

function OpenBadgesIssuancePage() {
  const navigate = useNavigate();
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
      <Button variant="contained" onClick={() => navigate('/docs')} sx={{ mr: 1 }}>View API Docs</Button>
      <Button variant="outlined" onClick={() => navigate('/open-badges-verification')}>Open Badges Verification</Button>
    </Box>
  );
}

export default OpenBadgesIssuancePage;
