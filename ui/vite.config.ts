import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import checker from 'vite-plugin-checker'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  const env = loadEnv(mode, process.cwd(), '')
  
  return {
    plugins: [
      react({
        // Use automatic JSX runtime (no need to import React)
        jsxRuntime: 'automatic',
      }),
      checker({
        typescript: true,
        eslint: {
          lintCommand: 'eslint . --ext .js,.jsx,.ts,.tsx',
        },
      }),
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
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
      rollupOptions: {
        output: {
          manualChunks: {
            'react-vendor': ['react', 'react-dom', 'react-router-dom'],
            'mui-vendor': ['@mui/material', '@mui/icons-material'],
          },
        },
      },
    },
    optimizeDeps: {
      include: ['react', 'react-dom', 'react-router-dom'],
    },
  }
})
