import { Box, Typography, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { SEOHead, softwareApplicationSchema } from '../seo';

function SdJwtVerificationPage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="SD-JWT Verification API"
        description="Verify SD-JWT credentials with selective disclosure checks, proof validation, and governed trust policy enforcement."
        canonicalPath="/sd-jwt-verification"
        structuredData={softwareApplicationSchema({ name: 'SD-JWT Verification API', description: 'API for selective-disclosure JWT verification.' })}
        keywords={['SD-JWT verification API', 'selective disclosure verification', 'OID4VP SD-JWT']}
      />
      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>SD-JWT Verification API</Typography>
      <Typography variant="body1" sx={{ mb: 3 }}>Validate selective disclosure proofs and policy compliance for modern wallet-based identity use cases.</Typography>
      <Button variant="contained" onClick={() => navigate('/docs')} sx={{ mr: 1 }}>View API Docs</Button>
      <Button variant="outlined" onClick={() => navigate('/trust-registry-infrastructure')}>See Trust Infrastructure</Button>
    </Box>
  );
}

export default SdJwtVerificationPage;
