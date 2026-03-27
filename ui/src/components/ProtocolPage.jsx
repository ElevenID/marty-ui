/**
 * Protocol Page
 *
 * Explains the Marty Identity Protocol (MIP) — the open standard
 * that defines primitives for verifiable digital identity management.
 * Features the Interactive Protocol Map and the learning curriculum.
 */

import { Box, Typography, Card, CardContent, CardActionArea, Grid, Paper, Button, Chip, Divider, LinearProgress } from '@mui/material';
import { SEOHead } from './seo';
import { protocolSchema } from './seo/structuredData';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import GitHubIcon from '@mui/icons-material/GitHub';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import GroupsIcon from '@mui/icons-material/Groups';
import GavelIcon from '@mui/icons-material/Gavel';
import PublicIcon from '@mui/icons-material/Public';
import InventoryIcon from '@mui/icons-material/Inventory';
import SchoolIcon from '@mui/icons-material/School';
import { PROTOCOL } from '../data/marketingContent';
import { GUIDE_CHAPTERS, GUIDE_ARTICLES_BY_CHAPTER } from '../data/guideContent';
import { InteractiveProtocolMap } from './diagrams';

const CHAPTER_ICONS = {
  School: <SchoolIcon />,
  Category: <MenuBookIcon />,
  Security: <CheckCircleIcon />,
  AccountTree: <ArrowForwardIcon />,
  CloudUpload: <PublicIcon />,
  Code: <InventoryIcon />,
};

function ProtocolPage() {
  const { t } = useTranslation('marketing');
  const navigate = useNavigate();

  return (
    <Box>
      <SEOHead
        title="Marty Identity Protocol (MIP) — Open Standard"
        description="MIP is a vendor-neutral, open specification for cryptographically verifiable digital identity management. Explore the interactive protocol map and learning curriculum."
        canonicalPath="/protocol"
        keywords={['Marty Identity Protocol', 'MIP', 'open standard', 'verifiable credentials', 'digital identity', 'open source', 'identity protocol']}
        structuredData={protocolSchema()}
      />

      {/* Hero */}
      <Box
        sx={{
          textAlign: 'center',
          py: { xs: 6, md: 8 },
          px: { xs: 2, md: 4 },
          background: 'linear-gradient(135deg, #1565c0 0%, #0d47a1 50%, #1a237e 100%)',
          color: 'white',
          borderRadius: 2,
          mb: 6,
        }}
      >
        <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1, mb: 2, flexWrap: 'wrap' }}>
          <Chip
            label={t('protocol.badge', 'Open Standard')}
            sx={{ bgcolor: 'rgba(255,255,255,0.15)', color: 'white', fontWeight: 700 }}
          />
          <Chip
            label={t('protocol.version', { version: PROTOCOL.version, status: PROTOCOL.status, defaultValue: `v${PROTOCOL.version} — ${PROTOCOL.status}` })}
            variant="outlined"
            sx={{ borderColor: 'rgba(255,255,255,0.4)', color: 'white' }}
          />
          <Chip
            label={t('protocol.license', PROTOCOL.license)}
            variant="outlined"
            sx={{ borderColor: 'rgba(255,255,255,0.4)', color: 'white' }}
          />
        </Box>
        <Typography
          variant="h3"
          component="h1"
          gutterBottom
          fontWeight={800}
          sx={{ fontSize: { xs: '2rem', md: '2.75rem' } }}
        >
          {t('protocol.heroTitle', 'Built on an Open Standard')}
        </Typography>
        <Typography
          variant="h6"
          sx={{ maxWidth: 800, mx: 'auto', opacity: 0.92, mb: 4 }}
        >
          {t('protocol.heroSubtitle', PROTOCOL.tagline)}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<GitHubIcon />}
            href={PROTOCOL.githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              bgcolor: 'white',
              color: 'primary.dark',
              fontWeight: 700,
              '&:hover': { bgcolor: 'grey.100' },
            }}
          >
            {t('protocol.ctaGitHub', 'View on GitHub')}
          </Button>
          <Button
            variant="outlined"
            size="large"
            startIcon={<MenuBookIcon />}
            href={`${PROTOCOL.githubUrl}/blob/main/SPECIFICATION.md`}
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              borderColor: 'white',
              color: 'white',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', borderColor: 'white' },
            }}
          >
            {t('protocol.ctaSpec', 'Read the Specification')}
          </Button>
        </Box>
      </Box>

      {/* Core Thesis */}
      <Paper
        elevation={0}
        sx={{ p: 4, mb: 6, bgcolor: 'primary.50', borderRadius: 2, textAlign: 'center', border: '1px solid', borderColor: 'primary.100' }}
      >
        <Typography variant="h6" fontWeight={600} color="primary.dark" sx={{ fontStyle: 'italic', maxWidth: 900, mx: 'auto' }}>
          &ldquo;{PROTOCOL.thesis}&rdquo;
        </Typography>
      </Paper>

      {/* Interactive Protocol Map */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" fontWeight={800} textAlign="center" gutterBottom>
          Protocol Architecture
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          Hover to explore relationships between components. Click any node to read its guide article.
          Toggle between Concept and Implementation views.
        </Typography>
        <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
          <InteractiveProtocolMap />
        </Box>
      </Box>

      <Divider sx={{ mb: 8 }} />

      {/* Learning Curriculum */}
      <Box sx={{ mb: 8 }}>
        <Box sx={{ textAlign: 'center', mb: 5 }}>
          <Typography variant="h4" fontWeight={800} gutterBottom>
            Learn the Protocol
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 700, mx: 'auto' }}>
            Six progressive chapters take you from foundations through deployment.
            Each article is a focused, standalone guide with code examples and concept tags.
          </Typography>
        </Box>

        <Grid container spacing={3} sx={{ maxWidth: 1100, mx: 'auto' }}>
          {GUIDE_CHAPTERS.map((chapter) => {
            const articles = (GUIDE_ARTICLES_BY_CHAPTER[chapter.id] || [])
              .sort((a, b) => a.order - b.order);

            return (
              <Grid item xs={12} sm={6} md={4} key={chapter.id}>
                <Card
                  elevation={2}
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    transition: 'all 0.2s ease',
                    '&:hover': { transform: 'translateY(-4px)', boxShadow: 6 },
                    borderTop: `4px solid ${chapter.color}`,
                  }}
                >
                  <CardContent sx={{ flexGrow: 1, pb: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
                      <Box sx={{ color: chapter.color }}>
                        {CHAPTER_ICONS[chapter.icon] || <SchoolIcon />}
                      </Box>
                      <Chip
                        label={`Chapter ${chapter.id}`}
                        size="small"
                        sx={{ fontWeight: 700, bgcolor: `${chapter.color}15`, color: chapter.color }}
                      />
                    </Box>
                    <Typography variant="h6" fontWeight={700} gutterBottom>
                      {chapter.title}
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      <LinearProgress
                        variant="determinate"
                        value={0}
                        sx={{
                          flexGrow: 1,
                          height: 4,
                          borderRadius: 2,
                          bgcolor: 'grey.200',
                          '& .MuiLinearProgress-bar': { bgcolor: chapter.color },
                        }}
                      />
                      <Typography variant="caption" color="text.secondary">
                        {articles.length} articles
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                      {articles.slice(0, 4).map((article) => (
                        <Typography
                          key={article.slug}
                          variant="body2"
                          color="text.secondary"
                          sx={{
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 0.5,
                            '&:hover': { color: chapter.color },
                          }}
                          onClick={() => navigate(`/blog/${article.slug}`)}
                        >
                          <ArrowForwardIcon sx={{ fontSize: 12 }} />
                          {article.title}
                        </Typography>
                      ))}
                      {articles.length > 4 && (
                        <Typography variant="caption" color="text.disabled" sx={{ pl: 2.2 }}>
                          +{articles.length - 4} more
                        </Typography>
                      )}
                    </Box>
                  </CardContent>
                  <Box sx={{ p: 2, pt: 0 }}>
                    <Button
                      size="small"
                      endIcon={<ArrowForwardIcon />}
                      onClick={() => {
                        const first = articles[0];
                        if (first) navigate(`/blog/${first.slug}`);
                      }}
                      sx={{ color: chapter.color }}
                    >
                      Start chapter
                    </Button>
                  </Box>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      </Box>

      <Divider sx={{ mb: 8 }} />

      {/* Standards Alignment */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" fontWeight={800} textAlign="center" gutterBottom>
          {t('protocol.sectionStandards', 'Standards Alignment')}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 4, maxWidth: 800, mx: 'auto' }}>
          {t('protocol.standardsSubtitle', 'MIP unifies international identity standards into a single interoperability layer.')}
        </Typography>

        <Grid container spacing={2} sx={{ maxWidth: 900, mx: 'auto' }}>
          {PROTOCOL.standards.map((std) => (
            <Grid item xs={12} sm={6} key={std.name}>
              <Paper
                elevation={1}
                sx={{
                  p: 2,
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 1.5,
                  transition: 'all 0.2s ease',
                  '&:hover': { boxShadow: 3 },
                }}
              >
                <CheckCircleIcon color="success" sx={{ mt: 0.3, flexShrink: 0 }} />
                <Box>
                  <Typography variant="subtitle2" fontWeight={700}>{std.name}</Typography>
                  <Typography variant="body2" color="text.secondary">{std.coverage}</Typography>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ textAlign: 'center', mt: 3 }}>
          <Button
            variant="text"
            endIcon={<ArrowForwardIcon />}
            onClick={() => navigate('/standards')}
          >
            See our standards implementation
          </Button>
        </Box>
      </Box>

      <Divider sx={{ mb: 8 }} />

      {/* Open Governance */}
      <Box sx={{ mb: 8 }}>
        <Typography variant="h4" fontWeight={800} textAlign="center" gutterBottom>
          {t('protocol.sectionGovernance', 'Open Governance')}
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 4, maxWidth: 700, mx: 'auto' }}>
          {t('protocol.governanceSubtitle', 'No single organization controls the protocol. All decisions are made publicly on GitHub.')}
        </Typography>

        <Grid container spacing={3} sx={{ maxWidth: 800, mx: 'auto' }}>
          {[
            { icon: <GroupsIcon sx={{ fontSize: 32, color: 'primary.main' }} />, text: t('protocol.governanceModel', PROTOCOL.governance.model) },
            { icon: <GavelIcon sx={{ fontSize: 32, color: 'secondary.main' }} />, text: t('protocol.governanceContributions', 'Developer Certificate of Origin (DCO) — no CLA required') },
            { icon: <PublicIcon sx={{ fontSize: 32, color: 'info.main' }} />, text: t('protocol.governanceDecisions', 'All decisions made publicly on GitHub — no private steering committees') },
            { icon: <InventoryIcon sx={{ fontSize: 32, color: 'success.main' }} />, text: t('protocol.governanceCopyright', 'Copyright held by The MIP Authors') },
          ].map((item, idx) => (
            <Grid item xs={12} sm={6} key={idx}>
              <Paper elevation={1} sx={{ p: 3, display: 'flex', alignItems: 'center', gap: 2, height: '100%' }}>
                {item.icon}
                <Typography variant="body1">{item.text}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* CTA Footer */}
      <Box
        sx={{
          textAlign: 'center',
          py: 6,
          background: 'linear-gradient(135deg, #1565c0 0%, #1a237e 100%)',
          color: 'white',
          borderRadius: 2,
        }}
      >
        <Typography variant="h4" gutterBottom fontWeight={800}>
          {t('protocol.ctaTitle', 'Get Involved')}
        </Typography>
        <Typography variant="body1" sx={{ maxWidth: 600, mx: 'auto', mb: 4, opacity: 0.92 }}>
          {t('protocol.ctaDescription', 'MIP is Apache 2.0 licensed and open to contributions. Read the spec, file issues, or submit a PR.')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            size="large"
            startIcon={<GitHubIcon />}
            href={PROTOCOL.githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              bgcolor: 'white',
              color: 'primary.dark',
              fontWeight: 700,
              '&:hover': { bgcolor: 'grey.100' },
            }}
          >
            {t('protocol.ctaGitHub', 'View on GitHub')}
          </Button>
          <Button
            variant="outlined"
            size="large"
            startIcon={<MenuBookIcon />}
            href={`${PROTOCOL.githubUrl}/blob/main/SPECIFICATION.md`}
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              borderColor: 'white',
              color: 'white',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', borderColor: 'white' },
            }}
          >
            {t('protocol.ctaSpec', 'Read the Specification')}
          </Button>
          <Button
            variant="outlined"
            size="large"
            endIcon={<ArrowForwardIcon />}
            onClick={() => navigate('/identity')}
            sx={{
              borderColor: 'rgba(255,255,255,0.5)',
              color: 'white',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.1)', borderColor: 'white' },
            }}
          >
            How Digital Identity Works
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default ProtocolPage;
