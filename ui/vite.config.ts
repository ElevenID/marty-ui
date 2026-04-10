import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import checker from 'vite-plugin-checker'
import prerender from '@prerenderer/rollup-plugin'
import PuppeteerRenderer from '@prerenderer/renderer-puppeteer'
import Sitemap from 'vite-plugin-sitemap'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  const env = loadEnv(mode, process.cwd(), '')
  const isDev = mode === 'development'
  const disablePrerender = isDev || process.env.DISABLE_PRERENDER === '1'
  const port = Number(env.VITE_PORT || env.PORT || env.UI_DEV_PORT || 3000)
  
  return {
    resolve: {
      // Force all react-* and router packages to resolve to a single copy from this
      // project root. This prevents duplicate instances when @marty/blog (a symlinked
      // local package) carries its own node_modules with react-router-dom – which would
      // create a second RouterContext that has no access to the outer <BrowserRouter>.
      dedupe: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-router-dom', 'react-router'],
    },
    optimizeDeps: {
      include: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-router-dom', '@marty/subscriptions'],
      exclude: ['@marty/blog'],
    },
    plugins: [
      react(),
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
            '/verifiable-credential-api',
            '/eudi-wallet-verification',
            '/iso-18013-5-mdoc-verification',
            '/sd-jwt-verification',
            '/open-badges-verification',
            '/open-badges-issuance',
            '/trust-registry-infrastructure',
            '/identity',
            '/from-idv-to-verifiable-identity',
            '/standards',
            '/protocol',
            '/blog',
            '/blog/why-identity-needs-a-protocol',
            '/blog/trust-profiles-explained',
            '/blog/business-case-for-credential-portability',
            '/blog/cryptographic-trust-anchors-primer',
            '/blog/credential-templates-designing-what-gets-issued',
            '/blog/presentation-policies-minimum-disclosure',
            '/blog/eudi-wallet-readiness',
            '/blog/deployment-profiles-from-design-to-production',
            '/blog/zero-knowledge-predicates-identity',
            '/blog/flows-orchestrating-identity-lifecycle',
            '/blog/compliance-profiles-bridging-regulation',
            '/blog/sd-jwt-selective-disclosure-deep-dive',
            '/blog/cedar-policies-for-identity-governance',
            '/blog/introducing-mip',
            '/blog/mip-json-schemas-walkthrough',
            '/blog/post-quantum-readiness-in-identity',
            '/blog/building-trust-registries-at-scale',
            '/blog/offline-verification-design-patterns',
            '/blog/holder-binding-beyond-biometrics',
            '/blog/mip-and-open-badges-education-credentials',
            '/blog/conformance-testing-for-implementers',
            '/blog/revocation-strategies-compared',
            '/pricing',
            '/docs',
          ],
          renderer: new PuppeteerRenderer({
            renderAfterTime: 3000, // Wait for MUI CSS-in-JS hydration
            headless: true,
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
            '/verifiable-credential-api',
            '/eudi-wallet-verification',
            '/iso-18013-5-mdoc-verification',
            '/sd-jwt-verification',
            '/open-badges-verification',
            '/open-badges-issuance',
            '/trust-registry-infrastructure',
            '/identity',
            '/from-idv-to-verifiable-identity',
            '/standards',
            '/protocol',
            '/ai',
            '/what-is-verifiable-identity',
            '/what-is-credential-verification',
            '/what-is-open-badge',
            '/what-is-digital-credential',
            '/what-is-marty-protocol',
            '/blog',
            '/blog/why-identity-needs-a-protocol',
            '/blog/trust-profiles-explained',
            '/blog/business-case-for-credential-portability',
            '/blog/cryptographic-trust-anchors-primer',
            '/blog/credential-templates-designing-what-gets-issued',
            '/blog/presentation-policies-minimum-disclosure',
            '/blog/eudi-wallet-readiness',
            '/blog/deployment-profiles-from-design-to-production',
            '/blog/zero-knowledge-predicates-identity',
            '/blog/flows-orchestrating-identity-lifecycle',
            '/blog/compliance-profiles-bridging-regulation',
            '/blog/sd-jwt-selective-disclosure-deep-dive',
            '/blog/cedar-policies-for-identity-governance',
            '/blog/introducing-mip',
            '/blog/mip-json-schemas-walkthrough',
            '/blog/post-quantum-readiness-in-identity',
            '/blog/building-trust-registries-at-scale',
            '/blog/offline-verification-design-patterns',
            '/blog/holder-binding-beyond-biometrics',
            '/blog/mip-and-open-badges-education-credentials',
            '/blog/conformance-testing-for-implementers',
            '/blog/revocation-strategies-compared',
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
            '/login',
            '/auth/*',
          ],
          changefreq: 'weekly',
          priority: {
            '/': 1.0,
            '/product': 0.9,
            '/pricing': 0.9,
            '/standards': 0.8,
            '/docs': 0.8,
            '/ai': 0.8,
            '/what-is-verifiable-identity': 0.7,
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
    ],
    server: {
      port: port,
      host: '0.0.0.0', // Listen on all network interfaces
      strictPort: false,
      cors: true,
      allowedHosts: env.PUBLIC_DOMAIN ? [env.PUBLIC_DOMAIN, 'localhost'] : 'all',
      fs: {
        // Allow serving files from the marty-blog source (linked via file: dependency)
        allow: ['..', '../../marty-blog'],
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
      outDir: 'dist',
      sourcemap: true,
      chunkSizeWarningLimit: 1000, // Increase from default 500kB to 1000kB
      rollupOptions: {
        output: {
          manualChunks: {
            'react-vendor': ['react', 'react-dom', 'react-router-dom'],
            'mui-vendor': ['@mui/material', '@mui/icons-material', '@mui/x-date-pickers'],
            'chart-vendor': ['recharts'],
          },
        },
      },
    },
  }
})
