import { Box, Typography, Button, Paper, Grid, Card, CardContent, Chip } from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useNavigate } from 'react-router';
import { DISABLE_PUBLIC_GET_STARTED_BUTTONS, SHOW_PUBLIC_GET_STARTED_BUTTONS } from '@ui-public-config';
import FutureFeatureButton from '../FutureFeatureButton';
import { SEOHead, softwareApplicationSchema } from '../seo';

function EudiWalletVerificationPage() {
  const navigate = useNavigate();
  const structuredData = softwareApplicationSchema({
    name: 'EUDI Wallet Verification API',
    description: 'Evaluate the exact EUDI wallet, presentation profile, and trust requirements for a Marty integration.',
  });

  return (
    <Box>
      <SEOHead
        title="EUDI Wallet Verification API"
        description="Review EUDI wallet verification requirements and release-specific interoperability evidence. No blanket EUDI readiness or regulatory approval is implied."
        canonicalPath="/eudi-wallet-verification"
        structuredData={structuredData}
        keywords={['EUDI wallet verifier', 'EUDI wallet verification API', 'EU digital identity verification', 'trust registry infrastructure']}
      />

      <Box sx={{ textAlign: 'center', py: 7, mb: 5, background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)', color: 'white', borderRadius: 2 }}>
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">EUDI Wallet Verification API</Typography>
        <Typography variant="h6" sx={{ maxWidth: 860, mx: 'auto', opacity: 0.95 }}>
          Define the wallet, credential, presentation profile, and acceptance requirements your integration needs.
        </Typography>
      </Box>

      <Typography variant="body1" sx={{ mb: 4, fontSize: '1.05rem' }}>
        EUDI wallet integration depends on the exact wallet build, presentation profile, trust framework, and Marty release.
        Review the implementation and executed interoperability tests for that combination. This page does not claim
        blanket EUDI compatibility, certification, or regulatory approval.
      </Typography>

      <Grid container spacing={3} sx={{ mb: 5 }}>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6" gutterBottom>Issuer Authorization</Typography><Typography variant="body2" color="text.secondary">Validate issuer eligibility using trust registries and policy constraints.</Typography></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6" gutterBottom>Revocation & Status</Typography><Typography variant="body2" color="text.secondary">Check revocation and status resources before accepting credentials.</Typography></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6" gutterBottom>Selective Disclosure</Typography><Typography variant="body2" color="text.secondary">Enforce data minimization and proof requirements per use case.</Typography></CardContent></Card></Grid>
      </Grid>

      <Paper sx={{ p: 3, mb: 5, bgcolor: 'grey.50' }}>
        <Typography variant="h6" gutterBottom>Related Standards</Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {['EUDI ARF', 'OpenID4VP', 'W3C VC', 'SD-JWT', 'ISO 18013-5'].map((s) => <Chip key={s} label={s} color="primary" variant="outlined" />)}
        </Box>
      </Paper>

      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 6 }}>
        {SHOW_PUBLIC_GET_STARTED_BUTTONS && (
          <FutureFeatureButton
            variant="contained"
            disabled={DISABLE_PUBLIC_GET_STARTED_BUTTONS}
            onClick={() => navigate('/pricing')}
            disabledSx={{
              bgcolor: 'rgba(25, 118, 210, 0.14)',
              color: 'rgba(25, 118, 210, 0.52)',
            }}
          >
            Review Commercial Scope
          </FutureFeatureButton>
        )}
        <Button variant="outlined" onClick={() => navigate('/docs')}>View API Docs</Button>
        <Button variant="text" endIcon={<ArrowForwardIcon />} onClick={() => navigate('/trust-registry-infrastructure')}>Trust Registry Architecture</Button>
      </Box>
    </Box>
  );
}

export default EudiWalletVerificationPage;
