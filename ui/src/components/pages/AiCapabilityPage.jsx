import { Box, Typography, Paper, Grid, Chip, Button } from '@mui/material';
import { SEOHead } from '../seo';
import { softwareApplicationSchema, breadcrumbListSchema } from '../seo/structuredData';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import VerifiedIcon from '@mui/icons-material/Verified';
import SecurityIcon from '@mui/icons-material/Security';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';
import SchemaIcon from '@mui/icons-material/Schema';
import PolicyIcon from '@mui/icons-material/Policy';
import TerminalIcon from '@mui/icons-material/Terminal';
import { useNavigate } from 'react-router-dom';

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
    description: 'Evaluate trust policies against credential presentations. Supports minimum disclosure, zero-knowledge predicates, and compliance rules.',
  },
  {
    icon: <SchemaIcon sx={{ fontSize: 40 }} />,
    title: 'Credential Schema Lookup',
    description: 'Query available credential types, schemas, and templates. Retrieve trust framework requirements and supported credential formats.',
  },
];

const cliCommands = [
  {
    command: 'marty verify start',
    description: 'Start a credential verification session using a trust profile and presentation policy',
    example: 'marty verify start --trust-profile eudi-pid --credential ./cred.json',
  },
  {
    command: 'marty creds issue',
    description: 'Issue a verifiable credential or Open Badge from a credential template',
    example: 'marty creds issue --template university-degree --subject ./subject.json',
  },
  {
    command: 'marty trust list',
    description: 'List all trust profiles configured in your organization',
    example: 'marty trust list --json',
  },
  {
    command: 'marty ct inspect',
    description: 'Inspect a credential template to view its schema and configuration',
    example: 'marty ct inspect <template-id> --json',
  },
  {
    command: 'marty compliance list',
    description: 'List compliance profiles and their regulatory mappings',
    example: 'marty compliance list --json',
  },
  {
    command: 'marty flows list',
    description: 'List active identity flows and their current status',
    example: 'marty flows list --json',
  },
];

const useCases = [
  { title: 'Verify student credentials', description: 'An AI coding assistant runs marty verify to check a student\'s Open Badge before generating an enrollment integration.' },
  { title: 'Automate credential issuance', description: 'A CI/CD pipeline uses marty creds issue to automatically issue completion badges after a training course.' },
  { title: 'Query trust registries', description: 'An AI agent runs marty trust list --json to discover which issuers are trusted before processing a credential.' },
  { title: 'Inspect credential schemas', description: 'A developer copilot runs marty ct inspect to understand a credential template before generating integration code.' },
];

function AiCapabilityPage() {
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="AI-Accessible Identity Infrastructure — ElevenID"
        description="ElevenID provides programmable identity infrastructure for AI agents. Use the Marty CLI to verify credentials, issue badges, and evaluate trust policies from any AI coding assistant or automation pipeline."
        canonicalPath="/ai"
        keywords={['AI identity verification', 'AI agent credentials', 'verifiable credentials CLI', 'verifiable credentials API', 'AI trust infrastructure', 'credential verification AI', 'developer CLI identity']}
        structuredData={[
          softwareApplicationSchema({
            name: 'ElevenID AI Integration',
            description: 'AI-accessible identity infrastructure for verifying credentials, issuing badges, and evaluating trust policies via CLI and REST API.',
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
          ElevenID allows AI systems to verify credentials and identity claims
          through a programmable trust infrastructure. AI agents interact with ElevenID
          through the Marty CLI and REST API.
        </Typography>
      </Box>

      {/* Capabilities */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        What AI Systems Can Do
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
          { icon: <TerminalIcon />, name: 'Marty CLI', description: 'The primary interface for AI agents. Developer copilots and automation tools use the CLI to run identity operations from the terminal.', link: null },
          { icon: <IntegrationInstructionsIcon />, name: 'REST API', description: 'Standard HTTP endpoints for all operations. Full OpenAPI specification available for automated integration.', link: '/docs' },
          { icon: <SchemaIcon />, name: 'OpenAPI Spec', description: 'Machine-readable API specification. AI agents and developer tools can ingest the spec to generate integrations automatically.', link: '/openapi.yaml' },
        ].map((iface) => (
          <Grid item xs={12} sm={4} key={iface.name}>
            <Paper
              elevation={1}
              sx={{ p: 3, height: '100%', cursor: iface.link ? 'pointer' : 'default' }}
              onClick={() => iface.link && (iface.link.startsWith('/openapi') ? window.open(iface.link, '_blank') : navigate(iface.link))}
            >
              <Box sx={{ color: 'primary.main', mb: 1 }}>{iface.icon}</Box>
              <Typography variant="h6" gutterBottom fontWeight="bold">{iface.name}</Typography>
              <Typography variant="body2" color="text.secondary">{iface.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>

      {/* CLI Commands */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Marty CLI for AI Agents
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 1 }}>
        AI coding assistants like GitHub Copilot, Cursor, and Windsurf can run Marty CLI commands
        directly from the terminal. All commands support <code>--json</code> output for structured parsing.
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 3, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Quick Start</Typography>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`# Install and authenticate
npm install -g @elevenid/marty-cli
marty init
marty auth login

# Enable shell completions
marty completion zsh >> ~/.zshrc`}
        </Box>
      </Paper>
      <Box sx={{ mb: 6 }}>
        {cliCommands.map((cmd) => (
          <Paper key={cmd.command} elevation={0} sx={{ p: 2.5, mb: 2, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <Chip label="cli" size="small" color="primary" variant="outlined" />
              <Typography variant="subtitle1" fontWeight="bold" fontFamily="monospace">{cmd.command}</Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{cmd.description}</Typography>
            <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'text.secondary', m: 0, p: 1, bgcolor: 'grey.50', borderRadius: 1 }}>
              {cmd.example}
            </Box>
          </Paper>
        ))}
      </Box>

      {/* Example Agent Workflow */}
      <Typography variant="h4" component="h2" gutterBottom fontWeight="bold" sx={{ mb: 3 }}>
        Example: AI Agent Verification Workflow
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        A developer asks their AI assistant: &quot;Verify this credential against our EUDI trust profile.&quot;
      </Typography>
      <Paper elevation={0} sx={{ p: 3, mb: 2, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Agent runs</Typography>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`marty verify start \\
  --trust-profile eudi-pid \\
  --credential ./credential.json \\
  --json`}
        </Box>
      </Paper>
      <Paper elevation={0} sx={{ p: 3, mb: 6, bgcolor: 'grey.50', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>Response</Typography>
        <Box component="pre" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', overflow: 'auto', m: 0 }}>
{`{
  "verified": true,
  "trustProfile": "eudi-pid",
  "checks": [
    { "name": "signature", "passed": true },
    { "name": "expiration", "passed": true },
    { "name": "revocation", "passed": true },
    { "name": "issuer_trust", "passed": true }
  ]
}`}
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
        <TerminalIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
        <Typography variant="h5" gutterBottom fontWeight="bold">
          Get Started with the Marty CLI
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600, mx: 'auto' }}>
          Install the CLI, authenticate, and start running identity operations
          from your terminal or AI coding assistant.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button variant="contained" size="large" onClick={() => navigate('/docs')}>
            API Documentation
          </Button>
          <Button variant="outlined" size="large" href="/openapi.yaml" target="_blank">
            OpenAPI Spec
          </Button>
        </Box>
      </Paper>
    </Box>
  );
}

export default AiCapabilityPage;
