import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import checker from 'vite-plugin-checker'
import { visualizer } from 'rollup-plugin-visualizer'
import { fileURLToPath, URL } from 'node:url'
import { existsSync } from 'node:fs'
import { selfhostBuildContractPlugin } from './scripts/selfhost-build-contract.mjs'
import { productionBuildContract, productionBuildContractPlugin } from './scripts/production-build-contract.mjs'
import { webSurfaceBuildContractPlugin } from './scripts/web-surface-build-contract.mjs'
import { devServerOrigin } from './scripts/dev-server-origin.mjs'

function createManualChunk(id: string) {
  const normalizedId = id.replace(/\\/g, '/')

  if (normalizedId.includes('/commerce-extension/')) return 'commerce-extension'
  if (normalizedId.includes('/node_modules/@elevenid/marty-api-core/')) return 'api-core-vendor'
  if (normalizedId.includes('/node_modules/redoc/')) return 'docs-vendor'
  if (normalizedId.includes('/node_modules/@emotion/') || normalizedId.includes('/node_modules/stylis/')) return 'emotion-vendor'
  if (normalizedId.includes('/node_modules/@mui/icons-material/')) return 'mui-icons-vendor'
  if (normalizedId.includes('/node_modules/@mui/x-date-pickers/') || normalizedId.includes('/node_modules/date-fns/')) return 'mui-pickers-vendor'
  if (normalizedId.includes('/node_modules/@mui/') || normalizedId.includes('/node_modules/@popperjs/core/')) return 'mui-core-vendor'
  if (normalizedId.includes('/node_modules/react/') || normalizedId.includes('/node_modules/react-dom/') || normalizedId.includes('/node_modules/react-router/')) return 'react-vendor'
  if (normalizedId.includes('/node_modules/recharts/')) return 'chart-vendor'
  if (normalizedId.includes('/node_modules/i18next/') || normalizedId.includes('/node_modules/react-i18next/')) return 'i18n-vendor'
  if (normalizedId.includes('/node_modules/qrcode.react/')) return 'qr-vendor'

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

// MUI 9 publishes icon entry points as .mjs. Preserve compatibility with
// external packages compiled against the former .js icon entry points.
function muiIconMjsCompatibilityPlugin() {
  return {
    name: 'mui-icon-mjs-compatibility',
    enforce: 'pre' as const,
    resolveId(source: string) {
      if (!/^@mui\/icons-material\/.+\.js$/.test(source)) return null

      const iconName = source.slice('@mui/icons-material/'.length, -'.js'.length)
      const iconPath = fileURLToPath(new URL(`./node_modules/@mui/icons-material/${iconName}.mjs`, import.meta.url))
      if (existsSync(iconPath)) return iconPath

      const renamedIconPath = fileURLToPath(new URL(
        `./node_modules/@mui/icons-material/${iconName.replace(/Outline$/, 'Outlined')}.mjs`,
        import.meta.url,
      ))
      return existsSync(renamedIconPath) ? renamedIconPath : null
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
  const explicitSurface = process.env.MARTY_UI_SURFACE
  const surface = explicitSurface || 'application'
  if (surface !== 'application') {
    throw new Error('Only the application UI surface is available; build the marketing website from ElevenID/website')
  }
  const sourceSha = process.env.MARTY_UI_SHA || 'development'
  const pages = process.env.MARTY_PRODUCTION_PAGES || 'public'
  const commerceSha = process.env.MARTY_COMMERCE_SOURCE_SHA
  const port = Number(env.VITE_PORT || env.PORT || env.UI_DEV_PORT || 3000)
  const productionCommerceEntry = productionBuildContract({
    pages,
    surface,
    selfhost: isSelfhostBuild,
    extensionPath: process.env.MARTY_COMMERCE_EXTENSION_PATH,
    sourceSha: process.env.MARTY_COMMERCE_SOURCE_SHA,
  })
  const commerceExtensionPath = productionCommerceEntry
    || fileURLToPath(new URL('./src/extensions/commerce/publicStub.jsx', import.meta.url))
  const bundleAnalysisBaseName = isSelfhostBuild ? 'bundle-analysis-selfhost' : 'bundle-analysis-public'
  return {
    publicDir: 'public',
    define: { 'import.meta.env.VITE_WEBSITE_ASSET_BASE': JSON.stringify('/') },
    resolve: {
      alias: {
        '@ui-public-config': fileURLToPath(new URL(`./src/variants/publicConfig.${isSelfhostBuild ? 'selfhost' : 'application'}.js`, import.meta.url)),
        '@ui-public-routes': fileURLToPath(new URL(`./src/variants/publicSite.${isSelfhostBuild ? 'selfhost' : 'application'}.jsx`, import.meta.url)),
        '@marty/commerce-extension': commerceExtensionPath,
        'react-router-dom': 'react-router',
      },
      // Shared and private extension packages must use the host React, router,
      // and styling contexts instead of resolving a separate installed copy.
      dedupe: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-router',
        '@mui/material', '@mui/icons-material', '@emotion/react', '@emotion/styled', 'prop-types'],
    },
    optimizeDeps: {
      include: ['react', 'react-dom', 'react/jsx-runtime', 'react/jsx-dev-runtime', 'react-router'],
    },
    plugins: [
      muiIconMjsCompatibilityPlugin(),
      ...(isSelfhostBuild ? [selfhostBuildContractPlugin()] : [webSurfaceBuildContractPlugin({ surface, sourceSha, pages, commerceSha, commerceEntry: productionCommerceEntry })]),
      ...(productionCommerceEntry ? [productionBuildContractPlugin(productionCommerceEntry)] : []),
      react(),
      consoleEntryRewritePlugin(),
      ...(isDev ? [checker({
        // Match the production build's checked sources. The broad root config
        // includes test fixtures that do not currently type-check; Vitest owns
        // their live behavioral feedback.
        typescript: { tsconfigPath: 'tsconfig.build.json' },
        eslint: {
          lintCommand: 'eslint src --ext .js,.jsx',
        },
        // Shared source demos keep diagnostics in the terminal without a badge
        // over the product UI. Local development retains the existing overlay.
        overlay: env.MARTY_DEV_CHECKER_OVERLAY === '0' ? false : {
          initialIsOpen: false,
          position: 'br',
        },
      })] : []),
      
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
      ...devServerOrigin(env),
      fs: {
        // Allow serving sibling source packages linked via file: dependencies.
        allow: ['..'],
      },
      headers: {
        'Cache-Control': 'no-store',
      },
      proxy: {
        // Proxy /v1/* API requests to microservices gateway
        '/v1': {
          target: env.VITE_DEV_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          ws: true,
        },
        // Proxy /auth/* requests to the backend (OIDC flows)
        '/auth': {
          target: env.VITE_DEV_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          ws: true,
        },
        // Legacy /api/* proxy (for backwards compatibility during transition)
        '/api': {
          target: env.VITE_DEV_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          ws: true,
        },
        // Proxy health check
        '/health': {
          target: env.VITE_DEV_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
        },
        // Proxy OpenAPI schema for API documentation
        '/openapi.yaml': {
          target: env.VITE_DEV_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
          rewrite: () => '/openapi.json',
        },
        '/openapi.json': {
          target: env.VITE_DEV_PROXY_TARGET || env.VITE_API_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          secure: false,
        },
      },
    },
    build: {
      // Preserve the default build location consumed by local production Compose.
      // The explicit application command owns the portable dist-application output.
      outDir: isSelfhostBuild ? 'dist-selfhost' : explicitSurface ? 'dist-application' : 'dist',
      assetsDir: 'assets',
      sourcemap: !isSelfhostBuild && !productionCommerceEntry,
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
