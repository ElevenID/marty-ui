/**
 * Blog Post Page
 *
 * Renders an individual blog post by slug from the BLOG_POSTS data.
 * If the slug matches a guide article, delegates to ProtocolGuidePage.
 * Includes related articles based on matching category, and concept tags.
 */

import { Box, Typography, Paper, Chip, Button, Divider, Avatar, Grid, Card, CardContent, CardActionArea } from '@mui/material';
import { SEOHead } from './seo';
import { articleSchema } from './seo/structuredData';
import { useParams, useNavigate } from 'react-router-dom';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { BLOG_POSTS, BLOG_AUTHORS } from '../data/marketingContent';
import { GUIDE_ARTICLE_MAP, BLOG_POST_CONCEPT_TAGS } from '../data/guideContent';
import ProtocolGuidePage from './ProtocolGuidePage';

const TODAY = new Date().toISOString().split('T')[0];

const CATEGORY_COLORS = {
  Announcement: 'primary',
  Technical: 'info',
  Business: 'success',
  Cryptography: 'warning',
  Guide: 'secondary',
};

function BlogPostPage() {
  const { slug } = useParams();
  const navigate = useNavigate();

  // Delegate to ProtocolGuidePage for guide articles
  if (GUIDE_ARTICLE_MAP[slug]) {
    return <ProtocolGuidePage />;
  }

  const post = BLOG_POSTS.find((p) => p.slug === slug);
  const author = post ? (BLOG_AUTHORS[post.authorId] || {}) : {};
  const conceptTags = (BLOG_POST_CONCEPT_TAGS[slug] || []);

  // Related: same category, already published, not this post, up to 3
  const relatedPosts = post
    ? BLOG_POSTS.filter(
        (p) => p.slug !== post.slug && p.category === post.category && p.date <= TODAY,
      )
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 3)
    : [];

  if (!post) {
    return (
      <Box sx={{ textAlign: 'center', py: 10 }}>
        <Typography variant="h4" gutterBottom>Post not found</Typography>
        <Button variant="outlined" onClick={() => navigate('/blog')} startIcon={<ArrowBackIcon />}>
          Back to Blog
        </Button>
      </Box>
    );
  }

  const dateStr = new Date(post.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  return (
    <Box>
      <SEOHead
        title={post.title}
        description={post.summary}
        canonicalPath={`/blog/${post.slug}`}
        keywords={['MIP', 'identity protocol', post.category.toLowerCase(), 'verifiable credentials']}
        ogType="article"
        ogMeta={{
          'article:published_time': post.date,
          'article:author': author.name || 'The MIP Authors',
          'article:section': post.category,
        }}
        structuredData={articleSchema({
          headline: post.title,
          description: post.summary,
          datePublished: post.date,
          authorName: author.name || 'The MIP Authors',
          url: `https://elevenidllc.com/blog/${post.slug}`,
        })}
      />

      {/* Back link */}
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/blog')} sx={{ mb: 3 }}>
        All Posts
      </Button>

      {/* Post header */}
      <Paper elevation={0} sx={{ p: { xs: 3, md: 5 }, mb: 4, bgcolor: 'grey.50', borderRadius: 2 }}>
        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
          <Chip label={post.category} size="small" color={CATEGORY_COLORS[post.category] || 'primary'} sx={{ fontWeight: 600 }} />
          <Chip label={post.readTime} size="small" variant="outlined" />
          {conceptTags.map((tag) => (
            <Chip
              key={tag}
              label={tag}
              size="small"
              variant="outlined"
              color="default"
              onClick={() => navigate(`/blog?tag=${encodeURIComponent(tag)}`)}
              sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
            />
          ))}
        </Box>
        <Typography variant="h3" component="h1" fontWeight={800} gutterBottom sx={{ fontSize: { xs: '1.75rem', md: '2.5rem' } }}>
          {post.title}
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          {post.summary}
        </Typography>
        {/* Author + date metadata row */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Avatar
            src={author.avatarImage}
            sx={{ width: 40, height: 40, bgcolor: 'primary.main', fontSize: '0.85rem', cursor: 'pointer' }}
            onClick={() => navigate(`/authors/${post.authorId}`)}
          >
            {author.avatar || '?'}
          </Avatar>
          <Box>
            <Typography
              variant="body2"
              fontWeight={600}
              sx={{ cursor: 'pointer', '&:hover': { color: 'primary.main', textDecoration: 'underline' } }}
              onClick={() => navigate(`/authors/${post.authorId}`)}
            >
              {author.name || post.authorId}{author.title ? ` · ${author.title}` : ''}{author.subtitle ? ` — ${author.subtitle}` : ''}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {dateStr} · {post.readTime} · {post.category}
            </Typography>
          </Box>
        </Box>
      </Paper>

      <Divider sx={{ mb: 4 }} />

      {/* Post body */}
      <Box sx={{ maxWidth: 780, mx: 'auto' }}>
        {post.content.map((block, idx) => {
          if (block.type === 'heading') {
            return (
              <Typography key={idx} variant="h5" fontWeight={700} sx={{ mt: 4, mb: 2 }}>
                {block.text}
              </Typography>
            );
          }
          return (
            <Typography key={idx} variant="body1" paragraph sx={{ lineHeight: 1.85, fontSize: '1.05rem' }}>
              {block.text}
            </Typography>
          );
        })}
      </Box>

      {/* Author bio */}
      {author.bio && (
        <Paper variant="outlined" sx={{ p: 3, mt: 6, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
            <Avatar
              src={author.avatarImage}
              sx={{ width: 48, height: 48, bgcolor: 'primary.main', fontSize: '1rem', flexShrink: 0, cursor: 'pointer' }}
              onClick={() => navigate(`/authors/${post.authorId}`)}
            >
              {author.avatar}
            </Avatar>
            <Box sx={{ flex: 1 }}>
              <Typography
                variant="subtitle1"
                fontWeight={700}
                sx={{ cursor: 'pointer', '&:hover': { color: 'primary.main' } }}
                onClick={() => navigate(`/authors/${post.authorId}`)}
              >
                {author.name}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {author.title}{author.subtitle ? ` — ${author.subtitle}` : ''}
              </Typography>
              <Typography variant="body2" sx={{ mb: 1.5 }}>{author.bio}</Typography>
              {author.expertise && author.expertise.length > 0 && (
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1.5 }}>
                  {author.expertise.map((tag) => (
                    <Chip key={tag} label={tag} size="small" variant="outlined" sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }} />
                  ))}
                </Box>
              )}
              {author.disclosure && (
                <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                  {author.disclosure}
                </Typography>
              )}
            </Box>
          </Box>
        </Paper>
      )}

      {/* Related Articles */}
      {relatedPosts.length > 0 && (
        <Box sx={{ mt: 8 }}>
          <Divider sx={{ mb: 4 }} />
          <Typography variant="h5" fontWeight={700} gutterBottom>
            Related Articles
          </Typography>
          <Grid container spacing={3}>
            {relatedPosts.map((related) => {
              const relatedAuthor = BLOG_AUTHORS[related.authorId] || {};
              return (
                <Grid item xs={12} sm={6} md={4} key={related.slug}>
                  <Card
                    elevation={1}
                    sx={{
                      height: '100%',
                      borderRadius: 2,
                      transition: 'all 0.2s',
                      '&:hover': { transform: 'translateY(-3px)', boxShadow: 5 },
                    }}
                  >
                    <CardActionArea
                      onClick={() => navigate(`/blog/${related.slug}`)}
                      sx={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
                    >
                      <CardContent sx={{ flexGrow: 1 }}>
                        <Chip
                          label={related.category}
                          size="small"
                          color={CATEGORY_COLORS[related.category] || 'default'}
                          sx={{ mb: 1.5, fontWeight: 600 }}
                        />
                        <Typography variant="h6" fontWeight={700} gutterBottom sx={{ fontSize: '1rem', lineHeight: 1.4 }}>
                          {related.title}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontSize: '0.85rem' }}>
                          {related.summary}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {relatedAuthor.name || related.authorId} · {related.readTime}
                        </Typography>
                      </CardContent>
                    </CardActionArea>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        </Box>
      )}

      <Divider sx={{ my: 6 }} />

      {/* Footer nav */}
      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
        <Button variant="outlined" onClick={() => navigate('/blog')} startIcon={<ArrowBackIcon />}>
          All Posts
        </Button>
        <Button variant="contained" endIcon={<ArrowForwardIcon />} onClick={() => navigate('/protocol')}>
          Explore the Protocol
        </Button>
      </Box>
    </Box>
  );
}

export default BlogPostPage;

