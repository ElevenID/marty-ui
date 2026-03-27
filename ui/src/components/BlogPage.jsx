/**
 * Blog Page
 *
 * "Learn the Marty Protocol" structured guide section at top, followed by
 * featured post + filterable article grid with search.
 */

import { useState, useMemo, useCallback } from 'react';
import {
  Box, Typography, Card, CardContent, CardActionArea, Grid, Chip,
  Avatar, TextField, InputAdornment, Button, Divider, Paper,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import RssFeedIcon from '@mui/icons-material/RssFeed';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import SchoolIcon from '@mui/icons-material/School';
import GroupsIcon from '@mui/icons-material/Groups';
import { SEOHead } from './seo';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { BLOG_POSTS, BLOG_AUTHORS } from '../data/marketingContent';
import {
  GUIDE_CHAPTERS,
  GUIDE_ARTICLES_BY_CHAPTER,
} from '../data/guideContent';

const TODAY = new Date().toISOString().split('T')[0];

const CATEGORIES = ['All', 'Business', 'Technical', 'Cryptography', 'Guide', 'Announcement'];

const CATEGORY_COLORS = {
  Announcement: 'primary',
  Technical: 'info',
  Business: 'success',
  Cryptography: 'warning',
  Guide: 'secondary',
};

// ── Protocol Guide Section ─────────────────────────────────────────────────────

function GuideArticleCard({ article, navigate }) {
  return (
    <Card
      elevation={1}
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        borderRadius: 2,
        transition: 'all 0.18s ease',
        '&:hover': { transform: 'translateY(-3px)', boxShadow: 5 },
      }}
    >
      <CardActionArea
        onClick={() => navigate(`/blog/${article.slug}`)}
        sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
      >
        <CardContent sx={{ flexGrow: 1, p: 2.5 }}>
          <Typography variant="subtitle2" fontWeight={700} gutterBottom sx={{ lineHeight: 1.35 }}>
            {article.title}
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ mb: 2, lineHeight: 1.55, fontSize: '0.8rem' }}
          >
            {article.summary}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'primary.main' }}>
            <Typography variant="caption" fontWeight={700} color="primary">
              Read Guide
            </Typography>
            <ArrowForwardIcon sx={{ fontSize: 13 }} />
          </Box>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}

function ProtocolGuideSection({ navigate }) {
  const [activeChapter, setActiveChapter] = useState(1);
  const chapterArticles = GUIDE_ARTICLES_BY_CHAPTER[activeChapter] || [];

  return (
    <Box
      sx={{
        mb: 8,
        p: { xs: 3, md: 4 },
        borderRadius: 3,
        background: 'linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%)',
        border: '1px solid',
        borderColor: 'primary.100',
      }}
    >
      {/* Section header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
        <SchoolIcon color="primary" />
        <Typography variant="h5" fontWeight={800} color="primary.dark">
          Learn the Marty Protocol
        </Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3, ml: 4.5 }}>
        A structured guide to verifiable identity — six chapters, ordered for progressive learning.
      </Typography>

      {/* Chapter selector chips */}
      <Box sx={{ display: 'flex', gap: 0.75, mb: 3, flexWrap: 'wrap' }}>
        {GUIDE_CHAPTERS.map((ch) => (
          <Chip
            key={ch.id}
            label={`${ch.id}. ${ch.title}`}
            clickable
            color={activeChapter === ch.id ? 'primary' : 'default'}
            variant={activeChapter === ch.id ? 'filled' : 'outlined'}
            onClick={() => setActiveChapter(ch.id)}
            sx={{
              fontWeight: activeChapter === ch.id ? 700 : 500,
              bgcolor: activeChapter === ch.id ? undefined : 'background.paper',
            }}
          />
        ))}
      </Box>

      {/* Guide article cards for selected chapter */}
      <Grid container spacing={2}>
        {chapterArticles.map((article) => (
          <Grid item xs={12} sm={6} md={3} key={article.slug}>
            <GuideArticleCard article={article} navigate={navigate} />
          </Grid>
        ))}
      </Grid>

      {/* Footer link */}
      <Box sx={{ mt: 3, display: 'flex', alignItems: 'center', justifyContent: 'flex-end' }}>
        <Button
          size="small"
          startIcon={<MenuBookIcon />}
          onClick={() => navigate(`/blog/${(GUIDE_ARTICLES_BY_CHAPTER[1] || [])[0]?.slug}`)}
          variant="outlined"
          sx={{ bgcolor: 'background.paper' }}
        >
          Start from the beginning
        </Button>
      </Box>
    </Box>
  );
}

function PostCard({ post, featured = false, onClick }) {
  const author = BLOG_AUTHORS[post.authorId] || {};
  const isFuture = post.date > TODAY;
  const dateStr = new Date(post.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  if (featured) {
    return (
      <Card
        elevation={3}
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', md: 'row' },
          mb: 5,
          borderRadius: 2,
          overflow: 'hidden',
          transition: 'box-shadow 0.2s',
          '&:hover': { boxShadow: 8 },
        }}
      >
        {/* Colour accent panel */}
        <Box
          sx={{
            width: { md: 280 },
            minHeight: { xs: 140, md: 'auto' },
            flexShrink: 0,
            background: 'linear-gradient(135deg, #1565c0 0%, #0d47a1 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Typography variant="h2" sx={{ color: 'rgba(255,255,255,0.15)', fontWeight: 900, userSelect: 'none', fontSize: { xs: '4rem', md: '6rem' } }}>
            {author.avatar || 'MIP'}
          </Typography>
        </Box>
        <CardActionArea onClick={onClick} sx={{ flexGrow: 1 }}>
          <CardContent sx={{ p: { xs: 3, md: 4 } }}>
            <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
              <Chip label="Featured" size="small" color="primary" sx={{ fontWeight: 700 }} />
              <Chip label={post.category} size="small" color={CATEGORY_COLORS[post.category] || 'default'} variant="outlined" />
              <Chip label={post.readTime} size="small" variant="outlined" />
            </Box>
            <Typography variant="h4" fontWeight={800} gutterBottom sx={{ fontSize: { xs: '1.5rem', md: '2rem' }, lineHeight: 1.3 }}>
              {post.title}
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.7 }}>
              {post.summary}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <Avatar src={author.avatarImage} sx={{ width: 36, height: 36, bgcolor: 'primary.main', fontSize: '0.8rem' }}>{author.avatar}</Avatar>
                <Box>
                  <Typography variant="body2" fontWeight={600}>{author.name} · {author.title}</Typography>
                  <Typography variant="caption" color="text.secondary">{dateStr}</Typography>
                </Box>
              </Box>
              <Button variant="contained" endIcon={<ArrowForwardIcon />} size="small">
                Read Article
              </Button>
            </Box>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }

  return (
    <Card
      elevation={isFuture ? 0 : 2}
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        borderRadius: 2,
        opacity: isFuture ? 0.65 : 1,
        border: isFuture ? '1px dashed' : 'none',
        borderColor: 'grey.300',
        transition: 'all 0.2s',
        '&:hover': isFuture ? {} : { transform: 'translateY(-4px)', boxShadow: 6 },
      }}
    >
      <CardActionArea
        disabled={isFuture}
        onClick={onClick}
        sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
      >
        <CardContent sx={{ flexGrow: 1, p: 3 }}>
          <Box sx={{ display: 'flex', gap: 0.75, mb: 2, flexWrap: 'wrap' }}>
            <Chip label={post.category} size="small" color={CATEGORY_COLORS[post.category] || 'default'} sx={{ fontWeight: 600 }} />
            {isFuture && <Chip label="Coming Soon" size="small" sx={{ bgcolor: 'grey.200', fontWeight: 600 }} />}
          </Box>
          <Typography variant="h6" fontWeight={700} gutterBottom sx={{ lineHeight: 1.35 }}>
            {post.title}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5, lineHeight: 1.65 }}>
            {post.summary}
          </Typography>
          <Divider sx={{ mb: 2 }} />
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Avatar src={author.avatarImage} sx={{ width: 26, height: 26, fontSize: '0.7rem', bgcolor: 'primary.main' }}>{author.avatar || '?'}</Avatar>
              <Typography variant="caption" color="text.secondary" noWrap>
                {author.name || post.authorId} · {dateStr}
              </Typography>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ flexShrink: 0, fontStyle: 'italic' }}>
              {post.readTime}
            </Typography>
          </Box>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}

function BlogPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const categoryParam = searchParams.get('category') || 'All';
  const [search, setSearch] = useState('');

  const publishedPosts = useMemo(
    () => [...BLOG_POSTS].sort((a, b) => new Date(b.date) - new Date(a.date)),
    [],
  );

  const featuredPost = useMemo(
    () => publishedPosts.find((p) => p.date <= TODAY) || publishedPosts[0],
    [publishedPosts],
  );

  const setCategory = useCallback(
    (cat) => {
      setSearchParams(cat === 'All' ? {} : { category: cat });
    },
    [setSearchParams],
  );

  const gridPosts = useMemo(() => {
    let posts = publishedPosts.filter((p) => p.slug !== featuredPost?.slug);
    if (categoryParam !== 'All') {
      posts = posts.filter((p) => {
        const author = BLOG_AUTHORS[p.authorId];
        return p.category === categoryParam || author?.persona === categoryParam;
      });
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      posts = posts.filter(
        (p) =>
          p.title.toLowerCase().includes(q) ||
          p.summary.toLowerCase().includes(q) ||
          p.category.toLowerCase().includes(q),
      );
    }
    return posts;
  }, [publishedPosts, featuredPost, categoryParam, search]);

  return (
    <Box>
      <SEOHead
        title="Blog — Marty Identity Protocol"
        description="Technical insights, identity standards, and implementation guides from the MIP team."
        canonicalPath="/blog"
        keywords={['MIP blog', 'identity protocol', 'open standard', 'verifiable credentials', 'digital identity']}
      />

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
          <Box>
            <Typography variant="h3" component="h1" fontWeight={900} gutterBottom>
              Blog
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 560 }}>
              Technical insights, identity standards, and implementation guides.
            </Typography>
          </Box>
          <Button
            component="a"
            href="/blog/rss.xml"
            startIcon={<RssFeedIcon />}
            variant="outlined"
            size="small"
            sx={{ flexShrink: 0 }}
          >
            RSS Feed
          </Button>
          <Button
            onClick={() => navigate('/authors')}
            startIcon={<GroupsIcon />}
            variant="outlined"
            size="small"
            sx={{ flexShrink: 0 }}
          >
            Authors
          </Button>
        </Box>
      </Box>

      {/* Protocol Guide Section */}
      <ProtocolGuideSection navigate={navigate} />

      <Divider sx={{ mb: 6 }}>
        <Chip label="Recent Articles" size="small" sx={{ fontWeight: 600 }} />
      </Divider>

      {/* Featured Post */}
      {featuredPost && (
        <PostCard
          post={featuredPost}
          featured
          onClick={() => navigate(`/blog/${featuredPost.slug}`)}
        />
      )}

      {/* Category Tabs + Search row */}
      <Box
        sx={{
          display: 'flex',
          gap: 2,
          mb: 4,
          alignItems: 'center',
          flexWrap: 'wrap',
        }}
      >
        <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap', flexGrow: 1 }}>
          {CATEGORIES.map((cat) => (
            <Chip
              key={cat}
              label={cat}
              clickable
              color={categoryParam === cat ? 'primary' : 'default'}
              variant={categoryParam === cat ? 'filled' : 'outlined'}
              onClick={() => setCategory(cat)}
              sx={{ fontWeight: categoryParam === cat ? 700 : 400 }}
            />
          ))}
        </Box>
        <TextField
          size="small"
          placeholder="Search articles…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ minWidth: 220 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {/* Post Grid */}
      <Grid container spacing={3}>
        {gridPosts.map((post) => (
          <Grid item xs={12} sm={6} md={4} key={post.slug}>
            <PostCard
              post={post}
              onClick={() => post.date <= TODAY && navigate(`/blog/${post.slug}`)}
            />
          </Grid>
        ))}
      </Grid>

      {gridPosts.length === 0 && (
        <Paper elevation={0} sx={{ p: 6, textAlign: 'center', bgcolor: 'grey.50', borderRadius: 2, mt: 2 }}>
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No articles match your search.
          </Typography>
          <Button onClick={() => { setSearch(''); setCategory('All'); }}>Clear filters</Button>
        </Paper>
      )}
    </Box>
  );
}

export default BlogPage;

