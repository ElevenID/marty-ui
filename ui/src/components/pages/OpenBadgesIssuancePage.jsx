import { Box, Typography, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { SEOHead, softwareApplicationSchema } from '../seo';

function OpenBadgesIssuancePage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="Open Badges 3.0 Issuance API"
        description="Issue Open Badges 3.0 as W3C Verifiable Credentials with lifecycle management, compliance policies, and wallet-ready delivery."
        canonicalPath="/open-badges-issuance"
        structuredData={softwareApplicationSchema({ name: 'Open Badges Issuance API', description: 'Open Badges 3.0 issuance and lifecycle infrastructure.' })}
        keywords={['Open Badges issuance API', 'W3C VC issuance', 'education credential issuance']}
      />
      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>Open Badges 3.0 Issuance Infrastructure</Typography>
      <Typography variant="body1" sx={{ mb: 3 }}>
        Issue standards-based Open Badges with credential templates, governance rules, revocation controls, and wallet-delivery support.
      </Typography>
      <Button variant="contained" onClick={() => navigate('/docs')} sx={{ mr: 1 }}>View API Docs</Button>
      <Button variant="outlined" onClick={() => navigate('/open-badges-verification')}>Open Badges Verification</Button>
    </Box>
  );
}

export default OpenBadgesIssuancePage;
