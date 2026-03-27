/**
 * Standards Page
 * 
 * Explains why standards matter and shows the standards stack
 * that ElevenID LLC is built on
 */

import { Box, Typography, Card, CardContent, Grid, Paper, Button } from '@mui/material';
import { SEOHead } from './seo';
import { STANDARDS_INFO, STANDARDS_STRATEGIC } from '../data/marketingContent';
import { StandardsStackDiagram } from './diagrams';
import PortableWifiOffIcon from '@mui/icons-material/PortableWifiOff';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import GitHubIcon from '@mui/icons-material/GitHub';
import { useNavigate } from 'react-router-dom';

const ICON_MAP = {
  'Portability': <PortableWifiOffIcon sx={{ fontSize: 48 }} />,
  'Trust': <VerifiedUserIcon sx={{ fontSize: 48 }} />,
  'Longevity': <TrendingUpIcon sx={{ fontSize: 48 }} />,
  'Interoperability': <IntegrationInstructionsIcon sx={{ fontSize: 48 }} />,
};

function StandardsPage() {
  const navigate = useNavigate();

  return (
    <Box>
      {/* SEO Meta Tags */}
      <SEOHead
        title="Identity Standards & Interoperability"
        description="Standards-based verifiable identity infrastructure built on ISO 18013-5, W3C VC, EUDI Wallet, OpenID4VP, and Open Badges. Portable, interoperable, and future-proof."
        canonicalPath="/standards"
        keywords={['identity standards', 'ISO 18013-5', 'W3C Verifiable Credentials', 'EUDI Wallet', 'OpenID4VP', 'Open Badges', 'interoperability']}
      />
      
      {/* Hero Section */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          mb: 6,
          background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          Standards & Interoperability
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          Built on international standards for trust, portability, and long-term viability
        </Typography>
      </Box>

      {/* Why This Matters for You */}
      <Paper elevation={0} sx={{ p: 4, mb: 6, bgcolor: 'grey.50', borderRadius: 2 }}>
        <Typography variant="h5" fontWeight="bold" gutterBottom color="primary">
          Why Standards Matter for Your Organization
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.7 }}>
          Standards aren&apos;t just technical specifications—they&apos;re the foundation for interoperable, 
          future-proof identity infrastructure.
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.7 }}>
          <strong>Standards prevent vendor lock-in.</strong> When you build on international standards like ISO 18013 
          and W3C Verifiable Credentials, your credentials work across different wallets, issuers, and verifiers—not 
          just within one vendor&apos;s ecosystem.
        </Typography>
        <Typography variant="body1" paragraph sx={{ fontSize: '1.05rem', lineHeight: 1.7 }}>
          <strong>Standards reduce risk.</strong> Government regulations (like eIDAS 2.0 in the EU) are increasingly 
          mandating standards-based identity systems. Building on standards today means compliance tomorrow.
        </Typography>
        <Typography variant="body1" sx={{ fontSize: '1.05rem', lineHeight: 1.7 }}>
          <strong>Standards save engineering time.</strong> Instead of building custom protocols for credential 
          exchange, trust establishment, and security, you leverage proven solutions with libraries, tools, 
          and community support.
        </Typography>
      </Paper>

      {/* Strategic Statement */}
      <Box sx={{ mb: 6 }}>
        <Paper elevation={0} sx={{ p: 3, mb: 2, bgcolor: 'primary.light', borderRadius: 2 }}>
          <Typography variant="h5" textAlign="center" fontWeight="bold" color="primary.dark">
            {STANDARDS_STRATEGIC.header}
          </Typography>
        </Paper>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ maxWidth: 800, mx: 'auto' }}>
          ElevenID LLC models standards as governed configuration—trust rules, credential formats, presentation policies, 
          and deployment behavior—rather than one-off integrations.
        </Typography>
      </Box>

      {/* Why Standards Matter - Cards */}
      <Box sx={{ mb: 8 }}>
        <Grid container spacing={4}>
          {STANDARDS_INFO.whyStandardsMatter.points.map((point) => (
            <Grid item xs={12} sm={6} md={3} key={point.title}>
              <Card sx={{ height: '100%', textAlign: 'center' }}>
                <CardContent sx={{ py: 4 }}>
                  <Box sx={{ color: 'primary.main', mb: 2 }}>
                    {ICON_MAP[point.title]}
                  </Box>
                  <Typography variant="h6" fontWeight="bold" gutterBottom>
                    {point.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {point.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* Standards Stack Diagram */}
      <Box sx={{ mb: 8 }}>
        <Paper elevation={2} sx={{ p: 4, bgcolor: 'grey.50' }}>
          <StandardsStackDiagram interactive={true} />
        </Paper>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mt: 3, maxWidth: 800, mx: 'auto' }}>
          Each layer maps to a different concern: frameworks define what identity means, formats define how claims are encoded, 
          protocols define how they move, and trust defines who is authorized. ElevenID LLC governs all four centrally.
        </Typography>
      </Box>

      {/* Detailed Standards by Layer */}
      <Box sx={{ mb: 6 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold" textAlign="center" sx={{ mb: 4 }}>
          Standards in Detail
        </Typography>

        <Grid container spacing={4}>
          {STANDARDS_INFO.layers.map((layer) => (
            <Grid item xs={12} md={6} key={layer.name}>
              <Card elevation={3} sx={{ height: '100%' }}>
                <CardContent>
                  <Typography variant="h5" fontWeight="bold" color="primary" gutterBottom>
                    {layer.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {layer.description}
                  </Typography>

                  <Box sx={{ mt: 3 }}>
                    {layer.standards.map((standard) => (
                      <Box key={standard.name} sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" fontWeight="bold">
                          {standard.name}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {standard.description}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* Standards-First Approach */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          bgcolor: 'primary.main',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Standards-First Architecture
        </Typography>
        <Typography variant="body1" sx={{ maxWidth: 800, mx: 'auto', mb: 2 }}>
          ElevenID LLC isn&apos;t a proprietary identity system—it&apos;s infrastructure that implements 
          international standards. Your credentials work across vendors, jurisdictions, 
          and use cases.
        </Typography>
        <Typography variant="body2" sx={{ maxWidth: 700, mx: 'auto', mb: 3, opacity: 0.9 }}>
          Standards define the rules; ElevenID LLC enforces them through centrally governed policies 
          executed consistently across APIs, wallets, and devices.
        </Typography>
        <Typography variant="body2" sx={{ maxWidth: 700, mx: 'auto', mb: 3, opacity: 0.85 }}>
          These standards are now unified in the <strong>Marty Identity Protocol (MIP)</strong>—an open, 
          vendor-neutral specification that formalizes how trust, credentials, policies, and deployment 
          work together.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/protocol')}
            endIcon={<ArrowForwardIcon />}
            sx={{ color: 'white', borderColor: 'white', '&:hover': { borderColor: 'white', bgcolor: 'rgba(255,255,255,0.1)' } }}
          >
            Explore the Protocol
          </Button>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/identity')}
            endIcon={<ArrowForwardIcon />}
            sx={{ color: 'white', borderColor: 'rgba(255,255,255,0.5)', '&:hover': { borderColor: 'white', bgcolor: 'rgba(255,255,255,0.1)' } }}
          >
            See How Standards Are Governed
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default StandardsPage;
