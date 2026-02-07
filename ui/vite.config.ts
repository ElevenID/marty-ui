import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import checker from 'vite-plugin-checker'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  const env = loadEnv(mode, process.cwd(), '')
  const isDev = mode === 'development'
  
  return {
    plugins: [
      react({
        // Use automatic JSX runtime (no need to import React)
        jsxRuntime: 'automatic',
      }),
      // Only enable checker overlay in development mode
      // This prevents ESLint/TS errors from showing in production builds
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
    ],
    server: {
      port: 3000,
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
    optimizeDeps: {
      include: ['react', 'react-dom', 'react-router-dom'],
    },
  }
})
