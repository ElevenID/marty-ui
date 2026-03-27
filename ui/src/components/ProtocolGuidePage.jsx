/**
 * Protocol Guide Page
 *
 * Renders guide articles from GUIDE_ARTICLES.
 * Features: sticky sidebar, chapter progress stepper, collapsible code blocks,
 * concept tags, and prev/next navigation between all guide articles.
 *
 * Rendered by BlogPostPage when the slug matches a guide article.
 */

import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Chip,
  Button,
  Divider,
  Stepper,
  Step,
  StepLabel,
  Collapse,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ListItemButton,
  ListItemText,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import CodeIcon from '@mui/icons-material/Code';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import SchoolIcon from '@mui/icons-material/School';
import { SEOHead } from './seo';
import {
  GUIDE_CHAPTERS,
  GUIDE_ARTICLES,
  GUIDE_ARTICLE_MAP,
  GUIDE_ARTICLE_SLUGS,
  GUIDE_ARTICLES_BY_CHAPTER,
} from '../data/guideContent';

const SIDEBAR_WIDTH = 256;

const TAG_COLORS = {
  foundation: 'info',
  credential: 'info',
  verification: 'info',
  'core-object': 'primary',
  'trust-profile': 'primary',
  'credential-template': 'primary',
  'presentation-policy': 'primary',
  'deployment-profile': 'default',
  governance: 'success',
  cryptography: 'warning',
  'trust-anchor': 'success',
  'trust-registry': 'success',
  cedar: 'success',
  'policy-engine': 'success',
  pki: 'success',
  flow: 'secondary',
  issuance: 'secondary',
  presentation: 'secondary',
  revocation: 'secondary',
  'selective-disclosure': 'warning',
  deployment: 'default',
  offline: 'default',
  compliance: 'success',
  implementation: 'info',
  oid4vci: 'info',
  oid4vp: 'info',
  mdoc: 'info',
  'iso-18013': 'info',
  'open-badges': 'info',
  announcement: 'primary',
  business: 'success',
};

// ── Code Block ─────────────────────────────────────────────────────────────────

function CodeBlock({ label, lang, code }) {
  const [open, setOpen] = useState(false);
  return (
    <Paper
      variant="outlined"
      sx={{ my: 3, borderRadius: 2, overflow: 'hidden', borderColor: 'grey.300' }}
    >
      <Box
        role="button"
        tabIndex={0}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setOpen((v) => !v)}
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1.5,
          bgcolor: 'grey.100',
          cursor: 'pointer',
          userSelect: 'none',
          '&:hover': { bgcolor: 'grey.200' },
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <CodeIcon fontSize="small" color="action" />
          <Typography variant="body2" fontWeight={600} color="text.secondary">
            {label}
          </Typography>
          <Chip
            label={lang}
            size="small"
            sx={{ height: 18, fontSize: '0.65rem', fontFamily: 'monospace' }}
          />
        </Box>
        <ExpandMoreIcon
          fontSize="small"
          color="action"
          sx={{
            transition: 'transform 0.2s',
            transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
          }}
        />
      </Box>
      <Collapse in={open}>
        <Box
          component="pre"
          sx={{
            m: 0,
            p: 2.5,
            bgcolor: '#1e1e2e',
            color: '#cdd6f4',
            fontSize: '0.78rem',
            fontFamily: '"Fira Code", "Cascadia Code", "Courier New", monospace',
            overflowX: 'auto',
            lineHeight: 1.65,
            whiteSpace: 'pre',
          }}
        >
          <code>{code}</code>
        </Box>
      </Collapse>
    </Paper>
  );
}

// ── Content Block ──────────────────────────────────────────────────────────────

function ContentBlock({ block }) {
  if (block.type === 'heading') {
    return (
      <Typography variant="h5" fontWeight={700} sx={{ mt: 4.5, mb: 1.5, scrollMarginTop: 80 }}>
        {block.text}
      </Typography>
    );
  }
  if (block.type === 'code') {
    return <CodeBlock label={block.label} lang={block.lang} code={block.code} />;
  }
  return (
    <Typography variant="body1" paragraph sx={{ lineHeight: 1.85, fontSize: '1.05rem' }}>
      {block.text}
    </Typography>
  );
}

// ── Sidebar ────────────────────────────────────────────────────────────────────

function GuideSidebar({ currentSlug, navigate }) {
  return (
    <Box sx={{ pt: 2, pb: 4 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, px: 2, mb: 2 }}>
        <MenuBookIcon color="primary" fontSize="small" />
        <Typography
          variant="caption"
          fontWeight={700}
          color="primary"
          sx={{ textTransform: 'uppercase', letterSpacing: '0.08em' }}
        >
          Protocol Guide
        </Typography>
      </Box>

      {GUIDE_CHAPTERS.map((ch) => (
        <Box key={ch.id} sx={{ mb: 1 }}>
          <Typography
            variant="caption"
            fontWeight={700}
            sx={{
              display: 'block',
              px: 2,
              pt: 1,
              pb: 0.5,
              color: 'text.secondary',
              textTransform: 'uppercase',
              letterSpacing: '0.07em',
              fontSize: '0.65rem',
            }}
          >
            {ch.id}. {ch.title}
          </Typography>
          {(GUIDE_ARTICLES_BY_CHAPTER[ch.id] || []).map((article) => {
            const isActive = article.slug === currentSlug;
            return (
              <ListItemButton
                key={article.slug}
                selected={isActive}
                onClick={() => navigate(`/blog/${article.slug}`)}
                sx={{
                  py: 0.55,
                  px: 2,
                  pl: 2.5,
                  borderRadius: 1,
                  mx: 0.5,
                  '&.Mui-selected': {
                    bgcolor: 'primary.50',
                    '&:hover': { bgcolor: 'primary.100' },
                  },
                }}
              >
                <ListItemText
                  primary={article.title}
                  primaryTypographyProps={{
                    variant: 'body2',
                    fontWeight: isActive ? 700 : 400,
                    color: isActive ? 'primary.main' : 'text.primary',
                    sx: { lineHeight: 1.4, fontSize: '0.84rem' },
                  }}
                />
              </ListItemButton>
            );
          })}
        </Box>
      ))}
    </Box>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

function ProtocolGuidePage() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const theme = useTheme();
  const isMd = useMediaQuery(theme.breakpoints.up('md'));

  const article = GUIDE_ARTICLE_MAP[slug];
  const currentIdx = GUIDE_ARTICLE_SLUGS.indexOf(slug);
  const prevArticle =
    currentIdx > 0 ? GUIDE_ARTICLE_MAP[GUIDE_ARTICLE_SLUGS[currentIdx - 1]] : null;
  const nextArticle =
    currentIdx < GUIDE_ARTICLE_SLUGS.length - 1
      ? GUIDE_ARTICLE_MAP[GUIDE_ARTICLE_SLUGS[currentIdx + 1]]
      : null;

  if (!article) {
    return (
      <Box sx={{ textAlign: 'center', py: 10 }}>
        <Typography variant="h4" gutterBottom>
          Guide article not found
        </Typography>
        <Button
          variant="outlined"
          onClick={() => navigate('/blog')}
          startIcon={<ArrowBackIcon />}
        >
          Back to Blog
        </Button>
      </Box>
    );
  }

  const chapter = GUIDE_CHAPTERS.find((c) => c.id === article.chapterId);
  const chapterArticles = GUIDE_ARTICLES_BY_CHAPTER[article.chapterId] || [];

  return (
    <Box sx={{ display: 'flex', gap: { md: 4 }, alignItems: 'flex-start' }}>
      <SEOHead
        title={`${article.title} — Marty Protocol Guide`}
        description={article.summary}
        canonicalPath={`/blog/${slug}`}
        keywords={['MIP guide', 'Marty Protocol', ...article.conceptTags]}
        ogType="article"
        ogMeta={{
          'article:section': `Chapter ${article.chapterId}: ${chapter?.title}`,
        }}
      />

      {/* ── Sticky sidebar (md+) */}
      {isMd && (
        <Box
          sx={{
            width: SIDEBAR_WIDTH,
            flexShrink: 0,
            position: 'sticky',
            top: 24,
            maxHeight: 'calc(100vh - 80px)',
            overflowY: 'auto',
            border: '1px solid',
            borderColor: 'divider',
            borderRadius: 2,
            bgcolor: 'background.paper',
          }}
        >
          <GuideSidebar currentSlug={slug} navigate={navigate} />
        </Box>
      )}

      {/* ── Main content */}
      <Box sx={{ flexGrow: 1, minWidth: 0 }}>
        {/* Back to blog */}
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/blog')}
          sx={{ mb: 2, color: 'text.secondary' }}
          size="small"
        >
          All Posts
        </Button>

        {/* Chapter progress stepper */}
        <Paper
          elevation={0}
          sx={{
            p: { xs: 2, md: 2.5 },
            mb: 3,
            bgcolor: 'primary.50',
            borderRadius: 2,
            border: '1px solid',
            borderColor: 'primary.100',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
            <SchoolIcon color="primary" sx={{ fontSize: 18 }} />
            <Typography
              variant="caption"
              fontWeight={700}
              color="primary"
              sx={{ textTransform: 'uppercase', letterSpacing: '0.08em' }}
            >
              Marty Protocol Guide
            </Typography>
          </Box>
          <Stepper
            activeStep={article.chapterId - 1}
            alternativeLabel
            sx={{
              '& .MuiStepLabel-label': { fontSize: { xs: '0.6rem', sm: '0.7rem' } },
              '& .MuiStepConnector-line': { borderTopWidth: 2 },
            }}
          >
            {GUIDE_CHAPTERS.map((ch) => {
              const firstInChapter = GUIDE_ARTICLES_BY_CHAPTER[ch.id]?.[0];
              return (
                <Step
                  key={ch.id}
                  onClick={() => firstInChapter && navigate(`/blog/${firstInChapter.slug}`)}
                  sx={{ cursor: 'pointer' }}
                >
                  <StepLabel>{ch.title}</StepLabel>
                </Step>
              );
            })}
          </Stepper>
        </Paper>

        {/* Article header */}
        <Paper
          elevation={0}
          sx={{ p: { xs: 3, md: 4 }, mb: 4, bgcolor: 'grey.50', borderRadius: 2 }}
        >
          <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
            <Chip
              label={chapter?.title}
              size="small"
              color="primary"
              sx={{ fontWeight: 700 }}
            />
            <Chip
              label={`${article.order} of ${chapterArticles.length}`}
              size="small"
              variant="outlined"
            />
            <Chip label={article.readTime} size="small" variant="outlined" />
          </Box>

          <Typography
            variant="h3"
            component="h1"
            fontWeight={800}
            gutterBottom
            sx={{ fontSize: { xs: '1.7rem', md: '2.2rem' }, lineHeight: 1.25 }}
          >
            {article.title}
          </Typography>

          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.7, mb: 2.5 }}>
            {article.summary}
          </Typography>

          {/* Concept tags */}
          {article.conceptTags.length > 0 && (
            <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
              {article.conceptTags.map((tag) => (
                <Chip
                  key={tag}
                  label={tag}
                  size="small"
                  variant="outlined"
                  color={TAG_COLORS[tag] || 'default'}
                  onClick={() => navigate(`/blog?tag=${encodeURIComponent(tag)}`)}
                  sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                />
              ))}
            </Box>
          )}
        </Paper>

        <Divider sx={{ mb: 4 }} />

        {/* Content body */}
        <Box sx={{ maxWidth: 780 }}>
          {article.content.map((block, idx) => (
            <ContentBlock key={idx} block={block} />
          ))}
        </Box>

        {/* Mobile: Browse All Guide Articles accordion */}
        {!isMd && (
          <Box sx={{ mt: 6 }}>
            <Accordion variant="outlined" sx={{ borderRadius: '8px !important' }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <MenuBookIcon fontSize="small" color="primary" />
                  <Typography variant="body2" fontWeight={700}>
                    Browse All Guide Articles
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ p: 0 }}>
                <GuideSidebar currentSlug={slug} navigate={navigate} />
              </AccordionDetails>
            </Accordion>
          </Box>
        )}

        {/* Prev / Next navigation */}
        <Divider sx={{ mt: 6, mb: 3 }} />
        <Box
          sx={{
            display: 'flex',
            gap: 2,
            justifyContent: 'space-between',
            alignItems: 'flex-start',
          }}
        >
          {prevArticle ? (
            <Button
              variant="outlined"
              onClick={() => navigate(`/blog/${prevArticle.slug}`)}
              sx={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                py: 1.5,
                px: 2.5,
                textAlign: 'left',
                maxWidth: 280,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.25 }}>
                <ArrowBackIcon sx={{ fontSize: 14 }} />
                <Typography variant="caption" color="text.secondary">
                  Previous
                </Typography>
              </Box>
              <Typography variant="body2" fontWeight={700} sx={{ whiteSpace: 'normal' }}>
                {prevArticle.title}
              </Typography>
            </Button>
          ) : (
            <Box />
          )}

          {nextArticle && (
            <Button
              variant="contained"
              onClick={() => navigate(`/blog/${nextArticle.slug}`)}
              sx={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-end',
                py: 1.5,
                px: 2.5,
                textAlign: 'right',
                ml: 'auto',
                maxWidth: 280,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.25 }}>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.8)' }}>
                  Next
                </Typography>
                <ArrowForwardIcon sx={{ fontSize: 14 }} />
              </Box>
              <Typography variant="body2" fontWeight={700} sx={{ whiteSpace: 'normal' }}>
                {nextArticle.title}
              </Typography>
            </Button>
          )}
        </Box>

        {/* Footer actions */}
        <Divider sx={{ my: 4 }} />
        <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Button
            variant="outlined"
            onClick={() => navigate('/blog')}
            startIcon={<ArrowBackIcon />}
          >
            All Posts
          </Button>
          <Button
            variant="outlined"
            startIcon={<AccountTreeIcon />}
            onClick={() => navigate(`/protocol#${article.slug}`)}
          >
            View in Protocol Map
          </Button>
          <Button
            variant="outlined"
            endIcon={<ArrowForwardIcon />}
            onClick={() => navigate('/protocol')}
          >
            Explore the Protocol
          </Button>
        </Box>
      </Box>
    </Box>
  );
}

export default ProtocolGuidePage;
