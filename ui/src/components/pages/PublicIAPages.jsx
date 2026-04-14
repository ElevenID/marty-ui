import { Box, Button, Chip, Divider, Grid, Paper, Typography } from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { Link as RouterLink } from 'react-router-dom';
import { SEOHead } from '../seo';
import {
  DEVELOPER_QUICKSTART,
  DEPLOYMENT_PLAYBOOKS,
  PRODUCTS,
  PROOF_STRIP,
  TRUST_SIGNALS,
} from '../../data/marketingContent';

function PageFrame({ title, description, canonicalPath, keywords, eyebrow, actions = [], children }) {
  return (
    <Box>
      <SEOHead title={title} description={description} canonicalPath={canonicalPath} keywords={keywords} />
      <Box
        sx={{
          textAlign: 'center',
          py: { xs: 6, md: 8 },
          px: { xs: 2, md: 4 },
          mb: 6,
          borderRadius: 2,
          color: 'common.white',
          background: 'linear-gradient(135deg, #0d47a1 0%, #1976d2 55%, #42a5f5 100%)',
        }}
      >
        <Typography variant="overline" sx={{ letterSpacing: 1.3, opacity: 0.78 }}>
          {eyebrow}
        </Typography>
        <Typography variant="h3" component="h1" gutterBottom fontWeight={800}>
          {title}
        </Typography>
        <Typography variant="h6" sx={{ maxWidth: 860, mx: 'auto', opacity: 0.92 }}>
          {description}
        </Typography>
        {actions.length > 0 && (
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap', mt: 4 }}>
            {actions.map((action) => (
              <Button
                key={action.path}
                component={RouterLink}
                to={action.path}
                variant={action.variant || 'contained'}
                size="large"
                startIcon={action.startIcon}
                endIcon={action.endIcon}
                sx={
                  action.variant === 'outlined'
                    ? {
                        borderColor: 'rgba(255,255,255,0.72)',
                        color: 'common.white',
                        '&:hover': {
                          borderColor: 'common.white',
                          bgcolor: 'rgba(255,255,255,0.08)',
                        },
                      }
                    : {
                        bgcolor: 'common.white',
                        color: 'primary.main',
                        '&:hover': { bgcolor: 'grey.100' },
                      }
                }
              >
                {action.label}
              </Button>
            ))}
          </Box>
        )}
      </Box>
      <Box sx={{ display: 'grid', gap: { xs: 5, md: 6 } }}>{children}</Box>
    </Box>
  );
}

function Section({ title, subtitle, children }) {
  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" fontWeight={800} gutterBottom>
          {title}
        </Typography>
        {subtitle ? (
          <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 780 }}>
            {subtitle}
          </Typography>
        ) : null}
      </Box>
      {children}
    </Box>
  );
}

const defaultActions = [
  { label: 'Start Verifying Credentials', path: '/developers', startIcon: <VerifiedUserIcon /> },
  { label: 'View Verification API', path: '/verifiable-credential-api', variant: 'outlined', endIcon: <ArrowForwardIcon /> },
];

const architectureLayers = [
  {
    title: 'Credential layer',
    description: 'Issue and verify W3C Verifiable Credentials, SD-JWT payloads, Open Badges, and ISO mDoc credentials from one platform surface.',
    bullets: ['W3C VC and SD-JWT support', 'ISO 18013-5 mDoc readiness', 'Credential lifecycle controls'],
  },
  {
    title: 'Trust layer',
    description: 'Trust profiles determine which issuers, keys, and registries a verifier is allowed to accept for a given deployment lane.',
    bullets: ['Issuer allow-lists', 'Trust registry integration', 'Auditable trust changes'],
  },
  {
    title: 'Policy layer',
    description: 'Presentation policies keep disclosure bounded and reproducible, so verifiers ask for the minimum evidence required by the operating context.',
    bullets: ['Selective disclosure', 'Presentation policy enforcement', 'Revocation and expiry checks'],
  },
  {
    title: 'Runtime layer',
    description: 'The same governed model runs through API endpoints, wallet presentations, self-hosted deployments, and offline checkpoint flows.',
    bullets: ['API and QR channels', 'Self-hosted or SaaS', 'Offline-ready runtime profiles'],
  },
];

const resourceLinks = [
  {
    title: 'Developer Docs',
    description: 'Reference docs, implementation notes, and API details for verification-first integrations.',
    path: '/docs',
    cta: 'Open Docs',
  },
  {
    title: 'Blog and Guides',
    description: 'Deployment guides, architectural essays, and standards explainers from the Marty team.',
    path: '/blog',
    cta: 'Read the Blog',
  },
  {
    title: 'Why Verifiable Identity',
    description: 'The positioning layer that explains why repeated IDV is the wrong long-term operating model.',
    path: '/why-verifiable-identity',
    cta: 'Read the Positioning',
  },
  {
    title: 'Architecture',
    description: 'See how trust, policy, protocols, and runtime fit together before you commit to an integration approach.',
    path: '/architecture',
    cta: 'Explore Architecture',
  },
  {
    title: 'Security',
    description: 'Review trust, infrastructure, and compliance controls that govern production verification surfaces.',
    path: '/security',
    cta: 'Review Security',
  },
  {
    title: 'Protocol Surface',
    description: 'Follow the standards map that connects wallets, credential formats, and verifier runtimes.',
    path: '/protocol',
    cta: 'View Protocols',
  },
];

export function SolutionsPage() {
  return (
    <PageFrame
      title="Verification solutions for real operating environments"
      description="Start from the verification moment, then pick the deployment path that matches retail, enterprise access, travel lanes, or portable membership ecosystems."
      canonicalPath="/solutions"
      keywords={['verification solutions', 'enterprise access', 'travel verification', 'age assurance', 'portable credentials']}
      eyebrow="Solutions"
      actions={defaultActions}
    >
      <Section
        title="Deployment playbooks"
        subtitle="Each route below already exists in the site as a deeper guide. Use the playbook view when you need the operational story, not just the standards list."
      >
        <Grid container spacing={3}>
          {DEPLOYMENT_PLAYBOOKS.items.map((item) => (
            <Grid item xs={12} md={6} key={item.slug}>
              <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Chip label={item.badge} color="primary" variant="outlined" sx={{ mb: 2, fontWeight: 700 }} />
                <Typography variant="h6" fontWeight={800} gutterBottom>
                  {item.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                  {item.proof}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2.5 }}>
                  {item.signals.map((signal) => (
                    <Chip key={signal} label={signal} size="small" />
                  ))}
                </Box>
                <Button component={RouterLink} to={`/blog/${item.slug}`} endIcon={<ArrowForwardIcon />}>
                  {item.cta}
                </Button>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Section>

      <Section
        title="Route buyers by operating need"
        subtitle="Keep the story anchored in the team and runtime that matters first, then branch into the deeper pages."
      >
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="overline" color="primary.main">
                Enterprise
              </Typography>
              <Typography variant="h6" fontWeight={800} gutterBottom>
                Reduce repeat KYC and access friction
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                Start with deployment guides, then move into product and security when the operating model is clear.
              </Typography>
              <Button component={RouterLink} to="/product" endIcon={<ArrowForwardIcon />}>
                Explore Product Surface
              </Button>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="overline" color="primary.main">
                Regulated lanes
              </Typography>
              <Typography variant="h6" fontWeight={800} gutterBottom>
                Understand trust and runtime before rollout
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                Architecture and standards pages explain how EUDI, ISO, and verifier policy fit into a production lane.
              </Typography>
              <Button component={RouterLink} to="/architecture" endIcon={<ArrowForwardIcon />}>
                View Architecture
              </Button>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="overline" color="primary.main">
                Developer teams
              </Typography>
              <Typography variant="h6" fontWeight={800} gutterBottom>
                Start with the verification request
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                Use the developer route when you want the request shape, decision model, and next integration step without the marketing detour.
              </Typography>
              <Button component={RouterLink} to="/developers" endIcon={<ArrowForwardIcon />}>
                Open Developer Path
              </Button>
            </Paper>
          </Grid>
        </Grid>
      </Section>
    </PageFrame>
  );
}

export function DevelopersPage() {
  return (
    <PageFrame
      title="Build the verification step first"
      description="The fastest credible path is to verify an existing credential payload in one request, then expand into wallet, QR, kiosk, or issuer flows when the operating model demands it."
      canonicalPath="/developers"
      keywords={['verification api', 'developers', 'verifiable credential api', 'wallet verification', 'identity api']}
      eyebrow="Developers"
      actions={[
        { label: 'View Verification API', path: '/verifiable-credential-api', startIcon: <VerifiedUserIcon /> },
        { label: 'Open Docs', path: '/docs', variant: 'outlined', endIcon: <ArrowForwardIcon /> },
      ]}
    >
      <Section
        title={DEVELOPER_QUICKSTART.title}
        subtitle={DEVELOPER_QUICKSTART.description}
      >
        <Paper sx={{ p: 3, borderRadius: 2, bgcolor: 'grey.950', color: 'common.white', overflow: 'auto' }}>
          <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.64)', letterSpacing: 1.2 }}>
            Quickstart
          </Typography>
          <Box component="pre" sx={{ m: 0, mt: 1.5, fontFamily: 'monospace', fontSize: '0.9rem', whiteSpace: 'pre-wrap' }}>
            {DEVELOPER_QUICKSTART.snippet}
          </Box>
        </Paper>
        <Grid container spacing={2} sx={{ mt: 1 }}>
          {DEVELOPER_QUICKSTART.bullets.map((bullet) => (
            <Grid item xs={12} md={4} key={bullet}>
              <Paper sx={{ p: 2.5, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  {bullet}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Section>

      <Section
        title="Choose the surface you implement next"
        subtitle="Verification API is the fastest start, but the same platform also covers issuance, kiosk, and holder flows when the deployment expands."
      >
        <Grid container spacing={3}>
          {PRODUCTS.map((product) => (
            <Grid item xs={12} md={6} key={product.id}>
              <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Typography variant="overline" color="primary.main">
                  {product.deployment.join(' / ')}
                </Typography>
                <Typography variant="h6" fontWeight={800} gutterBottom>
                  {product.name}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                  {product.useWhen}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {product.standards.slice(0, 3).map((standard) => (
                    <Chip key={standard} label={standard} size="small" />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Section>

      <Section
        title="Trace the runtime before you wire production"
        subtitle="Developers still need the system model: architecture explains the trust and policy layers, while security explains the deployment controls and compliance posture."
      >
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <Button component={RouterLink} to="/architecture" variant="outlined" endIcon={<ArrowForwardIcon />}>
            View Architecture
          </Button>
          <Button component={RouterLink} to="/security" variant="outlined" endIcon={<ArrowForwardIcon />}>
            Review Security
          </Button>
        </Box>
      </Section>
    </PageFrame>
  );
}

export function ArchitecturePage() {
  return (
    <PageFrame
      title="Architecture built around trust, policy, and runtime"
      description="The platform is organized so credential formats, trusted issuers, disclosure rules, and deployment profiles stay explicit instead of hiding inside one-off integrations."
      canonicalPath="/architecture"
      keywords={['identity architecture', 'trust architecture', 'verifiable credential architecture', 'policy engine', 'runtime architecture']}
      eyebrow="Architecture"
      actions={[
        { label: 'View Standards', path: '/standards', startIcon: <VerifiedUserIcon /> },
        { label: 'See Protocol Surface', path: '/protocol', variant: 'outlined', endIcon: <ArrowForwardIcon /> },
      ]}
    >
      <Section
        title="The system model"
        subtitle="These layers are what make verification reusable across products, verifier channels, and organizations."
      >
        <Grid container spacing={3}>
          {architectureLayers.map((layer) => (
            <Grid item xs={12} md={6} key={layer.title}>
              <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Typography variant="h6" fontWeight={800} gutterBottom>
                  {layer.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                  {layer.description}
                </Typography>
                <Box sx={{ display: 'grid', gap: 1 }}>
                  {layer.bullets.map((bullet) => (
                    <Typography key={bullet} variant="body2">
                      {bullet}
                    </Typography>
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Section>

      <Section
        title="Proof claims the product has to back up"
        subtitle="Keep the architecture discussion tied to claims the platform already makes publicly, rather than inventing a separate slide deck language."
      >
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {PROOF_STRIP.claims.map((claim) => (
            <Chip key={claim.label} label={`${claim.label} · ${claim.category}`} />
          ))}
        </Box>
      </Section>

      <Divider />

      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <Button component={RouterLink} to="/security" variant="outlined" endIcon={<ArrowForwardIcon />}>
          Review Security Controls
        </Button>
        <Button component={RouterLink} to="/why-verifiable-identity" variant="outlined" endIcon={<ArrowForwardIcon />}>
          Why Verifiable Identity
        </Button>
      </Box>
    </PageFrame>
  );
}

export function SecurityPage() {
  return (
    <PageFrame
      title="Security and governance stay in the product"
      description="Production verification depends on trusted issuers, bounded disclosure, secure key management, offline-safe runtime behavior, and a compliance model that does not require hand-waving."
      canonicalPath="/security"
      keywords={['identity security', 'trust governance', 'hsm integration', 'offline verification security', 'privacy by design']}
      eyebrow="Security"
      actions={[
        { label: 'View Architecture', path: '/architecture', startIcon: <VerifiedUserIcon /> },
        { label: 'Explore Product', path: '/product', variant: 'outlined', endIcon: <ArrowForwardIcon /> },
      ]}
    >
      <Section
        title="Trust signals"
        subtitle="These are the public controls the site already claims. The security page makes them easier to review in one place."
      >
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="h6" fontWeight={800} gutterBottom>
                Security
              </Typography>
              <Box sx={{ display: 'grid', gap: 1.25 }}>
                {TRUST_SIGNALS.security.map((item) => (
                  <Typography key={item} variant="body2" color="text.secondary">
                    {item}
                  </Typography>
                ))}
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="h6" fontWeight={800} gutterBottom>
                Infrastructure
              </Typography>
              <Box sx={{ display: 'grid', gap: 1.25 }}>
                {TRUST_SIGNALS.infrastructure.map((item) => (
                  <Typography key={item} variant="body2" color="text.secondary">
                    {item}
                  </Typography>
                ))}
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
              <Typography variant="h6" fontWeight={800} gutterBottom>
                Compliance
              </Typography>
              <Box sx={{ display: 'grid', gap: 1.25 }}>
                {TRUST_SIGNALS.compliance.map((item) => (
                  <Typography key={item} variant="body2" color="text.secondary">
                    {item}
                  </Typography>
                ))}
              </Box>
            </Paper>
          </Grid>
        </Grid>
      </Section>

      <Section
        title="Security review is still tied to the runtime"
        subtitle="The important point is not a checklist. It is that trust, keys, revocation, offline behavior, and privacy constraints stay part of the deployed verification lane."
      >
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {PROOF_STRIP.claims.map((claim) => (
            <Chip key={claim.label} label={claim.label} size="small" />
          ))}
        </Box>
      </Section>
    </PageFrame>
  );
}

export function ResourcesPage() {
  return (
    <PageFrame
      title="Docs, architecture, security, and rollout guides in one place"
      description="Use this hub when you need the right next page fast: implementation docs, deployment guides, architecture, security posture, or the positioning story behind reusable verification."
      canonicalPath="/resources"
      keywords={['resources', 'developer docs', 'identity architecture', 'security controls', 'deployment guides']}
      eyebrow="Resources"
      actions={[
        { label: 'Open Docs', path: '/docs', startIcon: <VerifiedUserIcon /> },
        { label: 'Read the Blog', path: '/blog', variant: 'outlined', endIcon: <ArrowForwardIcon /> },
      ]}
    >
      <Section
        title="Start with the page that matches the question"
        subtitle="The public IA is flatter now. This hub keeps the supporting surfaces visible without forcing them into the top-level navigation."
      >
        <Grid container spacing={3}>
          {resourceLinks.map((resource) => (
            <Grid item xs={12} md={6} lg={4} key={resource.path}>
              <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Typography variant="h6" fontWeight={800} gutterBottom>
                  {resource.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                  {resource.description}
                </Typography>
                <Button component={RouterLink} to={resource.path} endIcon={<ArrowForwardIcon />}>
                  {resource.cta}
                </Button>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Section>

      <Section
        title="Popular deployment guides"
        subtitle="These route directly to the existing guide content in the blog package, which keeps the new Resources surface grounded in pages that already ship."
      >
        <Grid container spacing={3}>
          {DEPLOYMENT_PLAYBOOKS.items.map((item) => (
            <Grid item xs={12} md={6} key={item.slug}>
              <Paper sx={{ p: 3, height: '100%', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Typography variant="overline" color="primary.main">
                  {item.badge}
                </Typography>
                <Typography variant="h6" fontWeight={800} gutterBottom>
                  {item.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                  {item.proof}
                </Typography>
                <Button component={RouterLink} to={`/blog/${item.slug}`} endIcon={<ArrowForwardIcon />}>
                  {item.cta}
                </Button>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Section>
    </PageFrame>
  );
}