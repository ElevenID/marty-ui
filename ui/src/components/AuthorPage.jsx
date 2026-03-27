/**
 * Author Page
 *
 * Individual persona page showing bio, expertise, and all posts by this author.
 * Accessible via /authors/:authorId.
 */

import { Box, Typography, Avatar, Chip, Paper, Grid, Card, CardContent, CardActionArea, Divider, Button } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useParams, useNavigate } from 'react-router-dom';
import { SEOHead } from './seo';
import { BLOG_POSTS, BLOG_AUTHORS } from '../data/marketingContent';

const TODAY = new Date().toISOString().split('T')[0];

const CATEGORY_COLORS = {
  Announcement: 'primary',
  Technical: 'info',
  Business: 'success',
  Cryptography: 'warning',
  Guide: 'secondary',
};

function AuthorPage() {
  const { authorId } = useParams();
  const navigate = useNavigate();

  const author = BLOG_AUTHORS[authorId];

  if (!author) {
    return (
      <Box sx={{ textAlign: 'center', py: 10 }}>
        <Typography variant="h4" gutterBottom>Author not found</Typography>
        <Button variant="outlined" onClick={() => navigate('/authors')} startIcon={<ArrowBackIcon />}>
          All Authors
        </Button>
      </Box>
    );
  }

  const authorPosts = BLOG_POSTS
    .filter((p) => p.authorId === authorId && p.date <= TODAY)
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  return (
    <Box>
      <SEOHead
        title={`${author.name} — ${author.title}`}
        description={author.bio}
        canonicalPath={`/authors/${authorId}`}
        keywords={[author.name, author.title, 'MIP', 'identity protocol']}
      />

      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/authors')} sx={{ mb: 3 }}>
        All Authors
      </Button>

      {/* Author header */}
      <Paper
        elevation={0}
        sx={{
          p: { xs: 3, md: 5 },
          mb: 5,
          borderRadius: 3,
          background: 'linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%)',
          border: '1px solid',
          borderColor: 'primary.100',
        }}
      >
        <Box sx={{ display: 'flex', gap: 3, alignItems: 'flex-start', flexDirection: { xs: 'column', sm: 'row' } }}>
          <Avatar
            src={author.avatarImage}
            sx={{
              width: 96,
              height: 96,
              bgcolor: 'primary.main',
              fontSize: '2rem',
              fontWeight: 700,
              flexShrink: 0,
            }}
          >
            {author.avatar}
          </Avatar>
          <Box sx={{ flex: 1 }}>
            <Typography variant="h4" fontWeight={800} gutterBottom>
              {author.name}
            </Typography>
            <Typography variant="h6" color="primary.dark" gutterBottom sx={{ fontWeight: 600 }}>
              {author.title}{author.subtitle ? ` — ${author.subtitle}` : ''}
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8, maxWidth: 680 }}>
              {author.bio}
            </Typography>

            {/* Expertise tags */}
            {author.expertise && author.expertise.length > 0 && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ mb: 1, display: 'block', textTransform: 'uppercase', letterSpacing: 1 }}>
                  Areas of Expertise
                </Typography>
                <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
                  {author.expertise.map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      variant="outlined"
                      sx={{ fontFamily: 'monospace', fontSize: '0.75rem', bgcolor: 'background.paper' }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {/* Disclosure */}
            {author.disclosure && (
              <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic', display: 'block', mt: 1 }}>
                {author.disclosure}
              </Typography>
            )}
          </Box>
        </Box>
      </Paper>

      {/* Posts by this author */}
      <Typography variant="h5" fontWeight={700} gutterBottom>
        Posts by {author.name}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        {authorPosts.length} article{authorPosts.length !== 1 ? 's' : ''} published
      </Typography>

      {authorPosts.length === 0 ? (
        <Paper elevation={0} sx={{ p: 4, textAlign: 'center', bgcolor: 'grey.50', borderRadius: 2 }}>
          <Typography variant="body1" color="text.secondary">
            No published articles yet. Check back soon.
          </Typography>
        </Paper>
      ) : (
        <Grid container spacing={3}>
          {authorPosts.map((post) => {
            const dateStr = new Date(post.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
            return (
              <Grid item xs={12} sm={6} md={4} key={post.slug}>
                <Card
                  elevation={1}
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    borderRadius: 2,
                    transition: 'all 0.2s',
                    '&:hover': { transform: 'translateY(-3px)', boxShadow: 5 },
                  }}
                >
                  <CardActionArea
                    onClick={() => navigate(`/blog/${post.slug}`)}
                    sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
                  >
                    <CardContent sx={{ flexGrow: 1, p: 3 }}>
                      <Box sx={{ display: 'flex', gap: 0.75, mb: 2, flexWrap: 'wrap' }}>
                        <Chip
                          label={post.category}
                          size="small"
                          color={CATEGORY_COLORS[post.category] || 'default'}
                          sx={{ fontWeight: 600 }}
                        />
                      </Box>
                      <Typography variant="h6" fontWeight={700} gutterBottom sx={{ lineHeight: 1.35 }}>
                        {post.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.65 }}>
                        {post.summary}
                      </Typography>
                      <Divider sx={{ mb: 1.5 }} />
                      <Typography variant="caption" color="text.secondary">
                        {dateStr} · {post.readTime}
                      </Typography>
                    </CardContent>
                  </CardActionArea>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      <Divider sx={{ my: 6 }} />

      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
        <Button variant="outlined" onClick={() => navigate('/authors')} startIcon={<ArrowBackIcon />}>
          All Authors
        </Button>
        <Button variant="contained" endIcon={<ArrowForwardIcon />} onClick={() => navigate('/blog')}>
          Browse All Posts
        </Button>
      </Box>
    </Box>
  );
}

export default AuthorPage;
