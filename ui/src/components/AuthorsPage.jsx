/**
 * Authors Page
 *
 * Research institute directory of all AI research personas. Grid layout with
 * professional cards showing avatar images, bios, expertise, and post counts.
 */

import { Box, Typography, Card, CardContent, CardActionArea, Grid, Chip, Avatar, Divider, Button, Paper } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useNavigate } from 'react-router-dom';
import { SEOHead } from './seo';
import { BLOG_AUTHORS, BLOG_POSTS, BLOG_ROADMAP } from '../data/marketingContent';

const TODAY = new Date().toISOString().split('T')[0];

function AuthorsPage() {
  const navigate = useNavigate();
  const authorEntries = Object.entries(BLOG_AUTHORS);

  // Count total roadmap posts per author
  const roadmapCountByAuthor = {};
  BLOG_ROADMAP.forEach((phase) => {
    phase.posts.forEach((p) => {
      roadmapCountByAuthor[p.authorId] = (roadmapCountByAuthor[p.authorId] || 0) + 1;
    });
  });

  return (
    <Box>
      <SEOHead
        title="Research Authors — Marty Identity Protocol"
        description="Meet the AI research personas analyzing verifiable identity standards, cryptography, governance, and protocol design."
        canonicalPath="/authors"
        keywords={['MIP authors', 'identity research', 'protocol analysts', 'verifiable credentials']}
      />

      {/* Header */}
      <Box sx={{ mb: 2 }}>
        <Typography
          variant="overline"
          sx={{ fontWeight: 700, letterSpacing: 2, color: 'primary.main' }}
        >
          Authors / Research Team
        </Typography>
        <Typography variant="h3" component="h1" fontWeight={900} gutterBottom>
          Research Authors
        </Typography>
      </Box>

      {/* Intro block */}
      <Paper
        elevation={0}
        sx={{
          p: { xs: 3, md: 4 },
          mb: 5,
          borderRadius: 3,
          background: 'linear-gradient(135deg, #0D1B2A 0%, #1B2838 100%)',
          color: 'common.white',
        }}
      >
        <Typography variant="body1" sx={{ maxWidth: 720, lineHeight: 1.8 }}>
          The ElevenID research personas analyze standards, cryptography, governance, and
          protocol design that power modern verifiable identity systems. Each persona specializes
          in a domain of the Marty Identity Protocol — from passport PKI and wallet architecture
          to privacy research and trust infrastructure.
        </Typography>
        <Typography variant="caption" sx={{ mt: 2, display: 'block', opacity: 0.7 }}>
          Research personas maintained by ElevenID AI systems.
        </Typography>
      </Paper>

      {/* Author grid */}
      <Grid container spacing={3}>
        {authorEntries.map(([authorId, author]) => {
          const publishedCount = BLOG_POSTS.filter((p) => p.authorId === authorId && p.date <= TODAY).length;
          const plannedCount = roadmapCountByAuthor[authorId] || 0;

          return (
            <Grid item xs={12} sm={6} md={4} key={authorId}>
              <Card
                elevation={2}
                sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  borderRadius: 2,
                  transition: 'all 0.2s',
                  '&:hover': { transform: 'translateY(-4px)', boxShadow: 6 },
                }}
              >
                <CardActionArea
                  onClick={() => navigate(`/authors/${authorId}`)}
                  sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
                >
                  <CardContent sx={{ flexGrow: 1, p: 3 }}>
                    {/* Avatar + name */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <Avatar
                        src={author.avatarImage}
                        sx={{
                          width: 64,
                          height: 64,
                          bgcolor: 'primary.main',
                          fontSize: '1.2rem',
                          fontWeight: 700,
                        }}
                      >
                        {author.avatar}
                      </Avatar>
                      <Box>
                        <Typography variant="h6" fontWeight={700} sx={{ lineHeight: 1.3 }}>
                          {author.name}
                        </Typography>
                        <Typography variant="body2" color="primary.dark" fontWeight={600}>
                          {author.title}
                        </Typography>
                      </Box>
                    </Box>

                    {/* Bio excerpt */}
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{
                        mb: 2,
                        lineHeight: 1.6,
                        display: '-webkit-box',
                        WebkitLineClamp: 3,
                        WebkitBoxOrient: 'vertical',
                        overflow: 'hidden',
                      }}
                    >
                      {author.bio}
                    </Typography>

                    {/* Expertise chips */}
                    {author.expertise && (
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 2 }}>
                        {author.expertise.slice(0, 3).map((tag) => (
                          <Chip
                            key={tag}
                            label={tag}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.7rem', fontFamily: 'monospace' }}
                          />
                        ))}
                        {author.expertise.length > 3 && (
                          <Chip
                            label={`+${author.expertise.length - 3}`}
                            size="small"
                            sx={{ fontSize: '0.7rem' }}
                          />
                        )}
                      </Box>
                    )}

                    <Divider sx={{ mb: 1.5 }} />

                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Typography variant="caption" color="text.secondary">
                        {publishedCount} published · {plannedCount} planned
                      </Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'primary.main' }}>
                        <Typography variant="caption" fontWeight={700} color="primary">
                          View profile
                        </Typography>
                        <ArrowForwardIcon sx={{ fontSize: 13 }} />
                      </Box>
                    </Box>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      <Divider sx={{ my: 6 }} />

      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
        <Button variant="outlined" onClick={() => navigate('/blog')} startIcon={<ArrowBackIcon />}>
          Back to Blog
        </Button>
      </Box>
    </Box>
  );
}

export default AuthorsPage;
