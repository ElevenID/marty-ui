import { Box, Typography, Button, Paper, Chip } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { SEOHead, softwareApplicationSchema } from '../seo';

function IsoMdocVerificationPage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="ISO 18013-5 mDoc Verification API"
        description="Verify ISO 18013-5 mDoc credentials with issuer trust validation, revocation checks, and standards-based interoperability."
        canonicalPath="/iso-18013-5-mdoc-verification"
        structuredData={softwareApplicationSchema({ name: 'ISO 18013-5 mDoc Verification API', description: 'mDoc and mobile driver license verification API.' })}
        keywords={['ISO 18013-5 verification', 'mDoc verification API', 'mobile driving licence verifier']}
      />
      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>ISO 18013-5 mDoc Verification API</Typography>
      <Typography variant="body1" sx={{ mb: 3 }}>Verify mDoc credentials using policy-driven trust decisions and cryptographic validation pipelines for online and offline scenarios.</Typography>
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50' }}>
        {['ISO 18013-5', 'W3C VC', 'OpenID4VP', 'Revocation status'].map((x) => <Chip key={x} label={x} sx={{ mr: 1, mb: 1 }} />)}
      </Paper>
      <Button variant="contained" onClick={() => navigate('/docs')} sx={{ mr: 1 }}>View API Docs</Button>
      <Button variant="outlined" onClick={() => navigate('/pricing')}>Start Free</Button>
    </Box>
  );
}

export default IsoMdocVerificationPage;
