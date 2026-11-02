import { Box, Typography, Button, Paper, Chip } from '@mui/material';
import { useNavigate } from 'react-router';
import { DISABLE_PUBLIC_GET_STARTED_BUTTONS, SHOW_PUBLIC_GET_STARTED_BUTTONS } from '@ui-public-config';
import FutureFeatureButton from '../FutureFeatureButton';
import { SEOHead, softwareApplicationSchema } from '../seo';

function IsoMdocVerificationPage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="ISO 18013-5 mDoc Verification API"
        description="Review the format, presentation transport, trust configuration, and test evidence needed for an ISO 18013-5 mDoc integration with Marty."
        canonicalPath="/iso-18013-5-mdoc-verification"
        structuredData={softwareApplicationSchema({ name: 'ISO 18013-5 mDoc Verification API', description: 'Release-specific mDoc verification scope and evaluation requirements.' })}
        keywords={['ISO 18013-5 verification', 'mDoc verification API', 'mobile driving licence verifier']}
      />
      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>ISO 18013-5 mDoc Verification API</Typography>
      <Typography variant="body1" sx={{ mb: 3 }}>Evaluate the exact mDoc profile, device, transport, issuer trust, and release together. Online and offline behavior require separate testing; an ISO reference does not establish conformance or availability on every device.</Typography>
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'grey.50' }}>
        {['ISO 18013-5', 'W3C VC', 'OpenID4VP', 'Revocation status'].map((x) => <Chip key={x} label={x} sx={{ mr: 1, mb: 1 }} />)}
      </Paper>
      <Button variant="contained" onClick={() => navigate('/docs')} sx={{ mr: 1 }}>View API Docs</Button>
      {SHOW_PUBLIC_GET_STARTED_BUTTONS && (
        <FutureFeatureButton
          variant="outlined"
          disabled={DISABLE_PUBLIC_GET_STARTED_BUTTONS}
          onClick={() => navigate('/pricing')}
          disabledSx={{
            borderColor: 'rgba(25, 118, 210, 0.25)',
            color: 'rgba(25, 118, 210, 0.52)',
          }}
        >
          Review Commercial Scope
        </FutureFeatureButton>
      )}
    </Box>
  );
}

export default IsoMdocVerificationPage;
