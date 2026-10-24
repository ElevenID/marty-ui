import { Box, Typography, Paper, Grid, Button } from '@mui/material';
import { SEOHead } from '../seo';
import { softwareApplicationSchema, breadcrumbListSchema } from '../seo/structuredData';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import VerifiedIcon from '@mui/icons-material/Verified';
import SecurityIcon from '@mui/icons-material/Security';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';
import SchemaIcon from '@mui/icons-material/Schema';
import PolicyIcon from '@mui/icons-material/Policy';
import { useNavigate } from 'react-router';
import ProtocolSupportCatalog from './ProtocolSupportCatalog';

const capabilities = [
  {
    icon: <VerifiedIcon sx={{ fontSize: 40 }} />,
    title: 'Credential Verification',
    description: 'Verify the authenticity and validity of W3C Verifiable Credentials, SD-JWT credentials, ISO 18013-5 mDocs, and Open Badges programmatically.',
  },
  {
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    title: 'Credential Issuance',
    description: 'Issue verifiable credentials and Open Badges using configurable credential templates, trust profiles, and deployment profiles.',
  },
  {
    icon: <PolicyIcon sx={{ fontSize: 40 }} />,
    title: 'Trust Policy Evaluation',
    description: 'Evaluate credential presentations through explicit presentation policies and the trust and compliance constraints exposed by the deployment.',
  },
  {
    icon: <SchemaIcon sx={{ fontSize: 40 }} />,
    title: 'Credential Schema Lookup',
    description: 'Query available credential types, schemas, and templates. Retrieve trust framework requirements and supported credential formats.',
  },
];

const useCases = [
  { title: 'Gate integrations by support level', description: 'Read the protocol catalog before presenting a workflow so unsupported and partial concepts stay explicit.' },
  { title: 'Generate HTTP clients', description: 'Use the gateway-generated OpenAPI document as the source for operations and public request and response schemas.' },
  { title: 'Build tenant workflows', description: 'Follow the catalog API paths into authenticated organization-scoped template, profile, issuance, and verification operations.' },
  { title: 'Explain product limits', description: 'Show the catalog limitations next to derived or partial features instead of treating every protocol concept as implemented.' },
];

function AiCapabilityPage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="AI-Accessible Identity Infrastructure — ElevenID"
        description="ElevenID provides gateway-owned discovery and OpenAPI contracts for credential, identity, trust, issuance, and verification integrations."
        canonicalPath="/ai"
        keywords={['AI identity verification', 'AI agent credentials', 'verifiable credentials API', 'AI trust infrastructure', 'credential verification AI', 'identity API discovery']}
        structuredData={[
          softwareApplicationSchema({
            name: 'ElevenID AI Integration',
            description: 'Programmable identity infrastructure with gateway-owned support discovery and a generated REST API contract.',
            applicationCategory: 'SecurityApplication',
          }),
          breadcrumbListSchema([
            { name: 'Home', url: 'https://elevenidllc.com' },
            { name: 'AI Integration', url: 'https://elevenidllc.com/ai' },
          ]),
        ]}
      />

      {/* Hero */}
      <Box sx={{
        textAlign: 'center', py: 6, mb: 6,
        background: 'linear-gradient(135deg, #1976d2 0%, #7c4dff 100%)',
        color: 'white', borderRadius: 2,
      }}>
        <SmartToyIcon sx={{ fontSize: 56, mb: 2, opacity: 0.9 }} />
        <Typography variant="h3" component="h1" gutterBottom fontWeight="bold">
          Identity Infrastructure for AI Systems
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 800, mx: 'auto', opacity: 0.95 }}>
          ElevenID exposes credential and identity workflows through a programmable REST API.
          The gateway publishes the exact supported protocol concepts, routes, schemas, and
          qualification limits for this deployment.
        </Typography>
      </Box>

      {/* Capabilities */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        What API Consumers Can Do
      </Typography>
      <Grid container spacing={3} sx={{ mb: 6 }}>
        {capabilities.map((cap) => (
          <Grid item xs={12} sm={6} key={cap.title}>
            <Paper elevation={1} sx={{ p: 3, height: '100%' }}>
              <Box sx={{ color: 'primary.main', mb: 1 }}>{cap.icon}</Box>
              <Typography variant="h6" gutterBottom fontWeight="bold">{cap.title}</Typography>
              <Typography variant="body2" color="text.secondary">{cap.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* Interfaces */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Integration Interfaces
      </Typography>
      <Grid container spacing={3} sx={{ mb: 6 }}>
        {[
          { icon: <VerifiedIcon />, name: 'Support Catalog', description: 'Public deployment-specific support states, API paths, UI paths, schema references, and known limits.', link: '/v1/protocol-support' },
          { icon: <IntegrationInstructionsIcon />, name: 'REST API', description: 'Canonical HTTP endpoints with operation-level support and qualification limits published by the gateway.', link: '/docs' },
          { icon: <SchemaIcon />, name: 'OpenAPI Spec', description: 'Canonical public API description generated by the gateway from its route contract.', link: '/openapi.json' },
        ].map((iface) => (
          <Grid item xs={12} sm={4} key={iface.name}>
            <Paper
              elevation={1}
              sx={{ p: 3, height: '100%', cursor: iface.link ? 'pointer' : 'default' }}
              onClick={() => iface.link && (iface.link === '/docs' ? navigate(iface.link) : window.open(iface.link, '_blank'))}
            >
              <Box sx={{ color: 'primary.main', mb: 1 }}>{iface.icon}</Box>
              <Typography variant="h6" gutterBottom fontWeight="bold">{iface.name}</Typography>
              <Typography variant="body2" color="text.secondary">{iface.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 1 }}>
        Protocol Consumer Support
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Use the gateway-owned catalog to distinguish direct product support from derived views, partial surfaces, and protocol concepts that are not implemented by this product candidate.
      </Typography>
      <Box sx={{ mb: 6 }}>
        <ProtocolSupportCatalog />
      </Box>

      {/* Gateway discovery */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Discover Before Integrating
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 1 }}>
        Fetch the public support catalog first, then use the generated OpenAPI document for the
        selected operation. Treat each catalog limitation as part of the deployment contract.
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 6, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Public discovery</Typography>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`curl -fsS "$MARTY_BASE_URL/v1/protocol-support"
curl -fsS "$MARTY_BASE_URL/openapi.json"`}
        </Box>
      </Paper>

      {/* Use Cases */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        AI Use Cases
      </Typography>
      <Grid container spacing={2} sx={{ mb: 6 }}>
        {useCases.map((uc) => (
          <Grid item xs={12} sm={6} key={uc.title}>
            <Paper elevation={0} sx={{ p: 2.5, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>{uc.title}</Typography>
              <Typography variant="body2" color="text.secondary">{uc.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* CTA */}
      <Paper sx={{
        p: 4, textAlign: 'center', mb: 4, borderRadius: 2,
        background: 'linear-gradient(135deg, #f5f5f5 0%, #e8eaf6 100%)',
      }}>
        <IntegrationInstructionsIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
        <Typography variant="h5" gutterBottom fontWeight="bold">
          Build from the Gateway Contract
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
          Discover the supported protocol surface, inspect the generated schemas, and authenticate
          only when the selected operation requires an organization-scoped workflow.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button variant="contained" size="large" onClick={() => navigate('/docs')}>
            API Documentation
          </Button>
          <Button variant="outlined" size="large" href="/openapi.json" target="_blank" rel="noopener noreferrer">
            OpenAPI Spec
          </Button>
        </Box>
      </Paper>
    </Box>
  );
}

export default AiCapabilityPage;
