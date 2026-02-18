import { Box, Typography, Button, List, ListItem, ListItemText } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { SEOHead, softwareApplicationSchema } from '../seo';

function TrustRegistryPage() {
  const navigate = useNavigate();
  return (
    <Box>
      <SEOHead
        title="Trust Registry Infrastructure"
        description="Build governed trust registry infrastructure for credential issuance and verification, with issuer authorization and policy-based trust decisions."
        canonicalPath="/trust-registry-infrastructure"
        structuredData={softwareApplicationSchema({ name: 'Trust Registry Infrastructure', description: 'Policy-driven issuer trust and governance infrastructure.' })}
        keywords={['trust registry infrastructure', 'issuer trust governance', 'verifiable credential trust registry']}
      />

      <Typography variant="h3" component="h1" fontWeight="bold" sx={{ mb: 2 }}>Trust Registry Infrastructure</Typography>
      <Typography variant="body1" sx={{ mb: 3 }}>
        ElevenID LLC centralizes trust decisions so verifier and issuer applications do not require redeployments when trust participants,
        policies, or revocation requirements change.
      </Typography>
      <List sx={{ mb: 3 }}>
        <ListItem><ListItemText primary="Issuer authorization and trust profile governance" /></ListItem>
        <ListItem><ListItemText primary="Revocation and status policy enforcement" /></ListItem>
        <ListItem><ListItemText primary="Reusable trust across wallet, API, and kiosk channels" /></ListItem>
      </List>
      <Button variant="contained" onClick={() => navigate('/verifiable-credential-api')} sx={{ mr: 1 }}>Verification API</Button>
      <Button variant="outlined" onClick={() => navigate('/docs')}>View API Docs</Button>
    </Box>
  );
}

export default TrustRegistryPage;
