import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import checker from 'vite-plugin-checker'
import prerender from '@prerenderer/rollup-plugin'
import PuppeteerRenderer from '@prerenderer/renderer-puppeteer'
import { visualizer } from 'rollup-plugin-visualizer'
import Sitemap from 'vite-plugin-sitemap'
import { fileURLToPath, URL } from 'node:url'

function createManualChunk(id: string) {
  const normalizedId = id.replace(/\\/g, '/')

  if (normalizedId.includes('/node_modules/@marty/blog/')) return 'blog-vendor'
  if (normalizedId.includes('/node_modules/@marty/subscriptions/')) return 'subscriptions-vendor'
  if (normalizedId.includes('/node_modules/@elevenid/marty-api-core/')) return 'api-core-vendor'
  if (normalizedId.includes('/node_modules/redoc/')) return 'docs-vendor'
  if (normalizedId.includes('/node_modules/@emotion/') || normalizedId.includes('/node_modules/stylis/')) return 'emotion-vendor'
  if (normalizedId.includes('/node_modules/@mui/icons-material/')) return 'mui-icons-vendor'
  if (normalizedId.includes('/node_modules/@mui/x-date-pickers/') || normalizedId.includes('/node_modules/date-fns/')) return 'mui-pickers-vendor'
  if (normalizedId.includes('/node_modules/@mui/') || normalizedId.includes('/node_modules/@popperjs/core/')) return 'mui-core-vendor'
  if (normalizedId.includes('/node_modules/react/') || normalizedId.includes('/node_modules/react-dom/') || normalizedId.includes('/node_modules/react-router-dom/')) return 'react-vendor'
  if (normalizedId.includes('/node_modules/recharts/')) return 'chart-vendor'
  if (normalizedId.includes('/node_modules/i18next/') || normalizedId.includes('/node_modules/react-i18next/')) return 'i18n-vendor'
  if (normalizedId.includes('/node_modules/qrcode.react/') || normalizedId.includes('/node_modules/react-qr-scanner/')) return 'qr-vendor'

  return undefined
}

function isConsoleAppRoute(url = '') {
  const pathname = url.split('?')[0]

  if (!pathname.startsWith('/console')) {
    return false
  }

  return !/\.[a-z0-9]+$/i.test(pathname)
}

function consoleEntryRewritePlugin() {
  const rewriteConsoleRequest = (req: { url?: string }, _res: unknown, next: () => void) => {
    if (req.url && isConsoleAppRoute(req.url)) {
      req.url = '/console/index.html'
    }

    next()
  }

  return {
    name: 'console-entry-rewrite',
    configureServer(server: { middlewares: { use: (handler: typeof rewriteConsoleRequest) => void } }) {
      server.middlewares.use(rewriteConsoleRequest)
    },
    configurePreviewServer(server: { middlewares: { use: (handler: typeof rewriteConsoleRequest) => void } }) {
      server.middlewares.use(rewriteConsoleRequest)
    },
  }
}

// https://vitejs.dev/config/
export default defineConfig(async ({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  const env = loadEnv(mode, process.cwd(), '')
  const isDev = mode === 'development'
  const enableBundleAnalysis = mode === 'analyze' || process.env.ANALYZE_BUNDLE === '1'
  const isSelfhostBuild = mode === 'selfhost' || env.VITE_UI_VARIANT === 'selfhost'
  const disablePrerender = isDev || isSelfhostBuild || process.env.DISABLE_PRERENDER === '1'
  const prerenderDebug = process.env.PRERENDER_DEBUG === '1'
  const prerenderConcurrency = Number(process.env.PRERENDER_CONCURRENCY || 1)
  const port = Number(env.VITE_PORT || env.PORT || env.UI_DEV_PORT || 3000)
  const bundleAnalysisBaseName = isSelfhostBuild ? 'bundle-analysis-selfhost' : 'bundle-analysis-public'
  let authorRoutes = []
  let blogRoutes = []

  if (!isSelfhostBuild) {
    const [
      { BLOG_POSTS },
      { BLOG_AUTHORS },
      {
        BLOG_POST_CONCEPT_TAGS,
        BLOG_POST_STANDARDS_TAGS,
        GUIDE_ARTICLE_SLUGS,
        GUIDE_ARTICLES,
        GUIDE_CHAPTERS,
      },
      { ARTICLE_META, getBrowseVisiblePosts },
      { buildBlogTagPath },
    ] = await Promise.all([
      import('../../marty-blog/src/data/blogPosts.js'),
      import('../../marty-blog/src/data/blogAuthors.js'),
      import('../../marty-blog/src/data/guideContent.js'),
      import('../../marty-blog/src/data/articleMeta.js'),
      import('../../marty-blog/src/utils/blogTagRoutes.js'),
    ])

    const chapterById = Object.fromEntries(GUIDE_CHAPTERS.map((chapter) => [chapter.id, chapter]))
    const tagPaths = new Set()

    getBrowseVisiblePosts(BLOG_POSTS).forEach((post) => {
      const meta = ARTICLE_META[post.slug]
      const tags = new Set([
        ...(BLOG_POST_STANDARDS_TAGS[post.slug] || []),
        ...(BLOG_POST_CONCEPT_TAGS[post.slug] || []),
        ...(meta?.topic ? [meta.topic] : []),
      ])

      tags.forEach((tag) => {
        tagPaths.add(buildBlogTagPath(tag))
      })
    })

    GUIDE_ARTICLES.forEach((article) => {
      const tags = new Set([
        ...(article.conceptTags || []),
        ...(chapterById[article.chapterId]?.title ? [chapterById[article.chapterId].title] : []),
      ])

      tags.forEach((tag) => {
        tagPaths.add(buildBlogTagPath(tag))
      })
    })

    authorRoutes = ['/authors', ...Object.keys(BLOG_AUTHORS).map((authorId) => `/authors/${authorId}`)]
    blogRoutes = Array.from(
      new Set([
        '/blog',
        ...tagPaths,
        ...BLOG_POSTS.map(({ slug }) => `/blog/${slug}`),
        ...GUIDE_ARTICLE_SLUGS.map((slug) => `/blog/${slug}`),
      ]),
    )
  }
  
  return {
    resolve: {
      alias: {
        '@ui-public-config': fileURLToPath(new URL(`./src/variants/publicConfig.${isSelfhostBuild ? 'selfhost' : 'public'}.js`, import.meta.url)),
        '@ui-public-routes': fileURLToPath(new URL(`./src/variants/publicSite.${isSelfhostBuild ? 'selfhost' : 'public'}.jsx`, import.meta.url)),
      },
      // Force all react-* and router packages to resolve to a single copy from this
      // project root. This prevents duplicate instances when @marty/blog (a symlinked
      // local package) carries its own node_modules with react-router-dom – which would
      // create a second RouterContext that has no access to the outer <BrowserRouter>.
      dedupe: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-router-dom', 'react-router'],
    },
    optimizeDeps: {
      include: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-router-dom', '@marty/subscriptions'],
      exclude: isSelfhostBuild ? [] : ['@marty/blog'],
    },
    plugins: [
      react(),
      consoleEntryRewritePlugin(),
      ...(isDev ? [checker({
        typescript: true,
        eslint: {
          lintCommand: 'eslint . --ext .js,.jsx,.ts,.tsx',
        },
        overlay: {
          initialIsOpen: false,
          position: 'br',
        },
      })] : []),
      
      // Prerendering for SEO - only in production builds
      ...(!disablePrerender ? [
        prerender({
          routes: [
            '/',
            '/product',
            '/solutions',
            '/developers',
            '/architecture',
            '/security',
            '/resources',
            '/verifiable-credential-api',
            '/eudi-wallet-verification',
            '/iso-18013-5-mdoc-verification',
            '/sd-jwt-verification',
            '/open-badges-verification',
            '/open-badges-issuance',
            '/trust-registry-infrastructure',
            '/identity',
            '/why-verifiable-identity',
            '/from-idv-to-verifiable-identity',
            '/what-is-verifiable-identity',
            '/standards',
            '/protocol',
            '/privacy-policy',
            '/terms-of-service',
            ...blogRoutes,
            ...authorRoutes,
            '/pricing',
            '/docs',
          ],
          renderer: new PuppeteerRenderer({
            maxConcurrentRoutes: prerenderConcurrency,
            renderAfterDocumentEvent: 'app-rendered',
            timeout: 45000,
            skipThirdPartyRequests: true,
            headless: true,
            pageHandler: prerenderDebug
              ? (_page, route) => console.info(`[prerender] loaded ${route}`)
              : undefined,
            consoleHandler: prerenderDebug
              ? (route, message) => console.info(`[prerender] ${route} ${message.type()}: ${message.text()}`)
              : undefined,
          }),
          postProcess(route) {
            // Add prerender status meta tag
            route.html = route.html.replace(
              '</head>',
              '<meta name="prerender-status-code" content="200" /></head>'
            );
          },
        }),
        
        // Sitemap generation
        Sitemap({
          hostname: 'https://elevenidllc.com',
          dynamicRoutes: [
            '/',
            '/product',
            '/solutions',
            '/developers',
            '/architecture',
            '/security',
            '/resources',
            '/verifiable-credential-api',
            '/eudi-wallet-verification',
            '/iso-18013-5-mdoc-verification',
            '/sd-jwt-verification',
            '/open-badges-verification',
            '/open-badges-issuance',
            '/trust-registry-infrastructure',
            '/identity',
            '/why-verifiable-identity',
            '/standards',
            '/protocol',
            '/ai',
            '/what-is-credential-verification',
            '/what-is-open-badge',
            '/what-is-digital-credential',
            '/what-is-marty-protocol',
            '/privacy-policy',
            '/terms-of-service',
            ...blogRoutes,
            ...authorRoutes,
            '/pricing',
            '/docs',
          ],
          exclude: [
            '/console',
            '/console/*',
            '/applicant',
            '/applicant/*',
            '/admin',
            '/admin/*',
            '/vendor',
            '/vendor/*',
            '/dashboard',
            '/test-harness',
            '/login',
            '/auth/*',
          ],
          changefreq: 'weekly',
          priority: {
            '/': 1.0,
            '/product': 0.9,
            '/solutions': 0.9,
            '/developers': 0.9,
            '/pricing': 0.9,
            '/standards': 0.8,
            '/resources': 0.8,
            '/architecture': 0.8,
            '/security': 0.8,
            '/docs': 0.8,
            '/ai': 0.8,
            '/why-verifiable-identity': 0.8,
            '/what-is-credential-verification': 0.7,
            '/what-is-open-badge': 0.7,
            '/what-is-digital-credential': 0.7,
            '/what-is-marty-protocol': 0.7,
            '*': 0.7,
          },
          generateRobotsTxt: true,
          robots: [
            {
              userAgent: '*',
              allow: '/',
              disallow: [
                '/console',
                '/console/*',
                '/applicant',
                '/applicant/*',
                '/admin',
                '/admin/*',
                '/vendor',
                '/vendor/*',
                '/dashboard',
                '/test-harness',
                '/auth/*',
                '/api/*',
                '/v1/*',
              ],
            },
            // Explicitly allow AI crawlers
            { userAgent: 'GPTBot', allow: '/' },
            { userAgent: 'ChatGPT-User', allow: '/' },
            { userAgent: 'Google-Extended', allow: '/' },
            { userAgent: 'Anthropic-AI', allow: '/' },
            { userAgent: 'ClaudeBot', allow: '/' },
            { userAgent: 'PerplexityBot', allow: '/' },
            { userAgent: 'Cohere-AI', allow: '/' },
          ],
        }),
      ] : []),

      ...(!isDev && enableBundleAnalysis ? [
        visualizer({
          filename: `build/${bundleAnalysisBaseName}.html`,
          template: 'treemap',
          gzipSize: true,
          brotliSize: true,
          open: false,
        }),
        visualizer({
          filename: `build/${bundleAnalysisBaseName}.json`,
          template: 'raw-data',
          gzipSize: true,
          brotliSize: true,
        }),
      ] : []),
    ],
    server: {
      port: port,
      host: '0.0.0.0', // Listen on all network interfaces
      strictPort: false,
      cors: true,
      allowedHosts: env.PUBLIC_DOMAIN ? [env.PUBLIC_DOMAIN, 'localhost'] : 'all',
      fs: {
        // Allow serving sibling source packages linked via file: dependencies.
        allow: ['..', '../../marty-subscriptions', ...(!isSelfhostBuild ? ['../../marty-blog'] : [])],
      },
      headers: {
        'Cache-Control': 'no-store',
      },
      // When accessed via a public tunnel domain, the browser must connect
      // the HMR WebSocket to the public host via wss:// on port 443.
      // Without this, Vite tries ws://localhost:3000 which fails cross-origin.
      ...(env.PUBLIC_DOMAIN ? {
        hmr: {
          protocol: 'wss',
          host: env.PUBLIC_DOMAIN,
          clientPort: 443,
        },
      } : {}),
      proxy: {
        // Proxy /v1/* API requests to microservices gateway
        '/v1': {
          target: env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          ws: true,
        },
        // Proxy /auth/* requests to the backend (OIDC flows)
        '/auth': {
          target: env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          ws: true,
        },
        // Legacy /api/* proxy (for backwards compatibility during transition)
        '/api': {
          target: env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          ws: true,
        },
        // Proxy health check
        '/health': {
          target: env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
        },
        // Proxy OpenAPI schema for API documentation
        '/openapi.json': {
          target: env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
        },
      },
    },
    build: {
      outDir: isSelfhostBuild ? 'dist-selfhost' : 'dist',
      sourcemap: !isSelfhostBuild,
      chunkSizeWarningLimit: 1000, // Increase from default 500kB to 1000kB
      rollupOptions: {
        input: {
          main: fileURLToPath(new URL('./index.html', import.meta.url)),
          console: fileURLToPath(new URL('./console/index.html', import.meta.url)),
        },
        output: {
          manualChunks: createManualChunk,
        },
      },
    },
  }
})
