import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { existsSync } from 'fs'

const configDir = import.meta.dirname

function muiIconMjsCompatibilityPlugin() {
  return {
    name: 'mui-icon-mjs-compatibility',
    enforce: 'pre' as const,
    resolveId(source: string) {
      if (!/^@mui\/icons-material\/.+\.js$/.test(source)) return null

      const iconName = source.slice('@mui/icons-material/'.length, -'.js'.length)
      const iconPath = resolve(configDir, 'node_modules', '@mui', 'icons-material', `${iconName}.mjs`)
      if (existsSync(iconPath)) return iconPath

      const renamedIconPath = resolve(
        configDir,
        'node_modules',
        '@mui',
        'icons-material',
        `${iconName.replace(/Outline$/, 'Outlined')}.mjs`,
      )
      return existsSync(renamedIconPath) ? renamedIconPath : null
    },
  }
}

// https://vitest.dev/config/
export default defineConfig({
  plugins: [
    muiIconMjsCompatibilityPlugin(),
    react({
      jsxRuntime: 'automatic',
    }),
  ],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/i18nTestSetup.js', './src/test/setup.ts'],
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'src/test/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData',
        '**/*.test.{ts,tsx}',
        '**/*.spec.{ts,tsx}',
        '**/dist/',
      ],
      thresholds: {
        lines: 70,
        functions: 70,
        branches: 70,
        statements: 70,
      },
    },
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['node_modules', 'dist', '.idea', '.git', '.cache'],
    // Increase timeout for integration tests
    testTimeout: 30000,
    hookTimeout: 30000,
    server: {
      deps: {
        inline: ['@elevenid/marty-blog', 'use-sync-external-store'],
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(configDir, './src'),
      '@components': resolve(configDir, './src/components'),
      '@services': resolve(configDir, './src/services'),
      '@hooks': resolve(configDir, './src/hooks'),
      '@contexts': resolve(configDir, './src/contexts'),
      '@config': resolve(configDir, './src/config'),
      '@ui-public-config': resolve(configDir, './src/variants/publicConfig.public.js'),
      '@ui-public-routes': resolve(configDir, './src/variants/publicSite.public.jsx'),
      '@marty/commerce-extension': resolve(configDir, './src/extensions/commerce/publicStub.jsx'),
      '@test': resolve(configDir, './src/test'),
    },
  },
})
