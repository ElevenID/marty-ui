import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import checker from 'vite-plugin-checker'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  const env = loadEnv(mode, process.cwd(), '')
  const isDev = mode === 'development'
  const port = Number(env.VITE_PORT || env.PORT || env.UI_DEV_PORT || 3000)
  
  return {
    plugins: [
      react(),
      // Checker temporarily disabled for debugging
      /*
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
      */
    ],
    server: {
      port: port,
      host: true, // Listen on all network interfaces
      allowedHosts: [
        'localhost',
        '.localhost',
        'beta.elevenidllc.com',
        '.elevenidllc.com', // Allow all subdomains
      ],
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
