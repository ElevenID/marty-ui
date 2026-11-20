import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import sharedConfig from './vitest.config.ts'
import { APPLICATION_TEST_FILES } from './scripts/application-test-profile.mjs'

const configDir = import.meta.dirname

// Replace the surface-specific arrays explicitly. mergeConfig would concatenate
// setupFiles and retain the combined profile's marketing translation import.
export default defineConfig({
  ...sharedConfig,
  test: {
    ...sharedConfig.test,
    setupFiles: ['./src/test/i18nApplicationTestSetup.js', './src/test/setup.ts'],
    include: [...APPLICATION_TEST_FILES],
    server: {
      ...sharedConfig.test?.server,
      deps: {
        ...sharedConfig.test?.server?.deps,
        inline: ['use-sync-external-store'],
      },
    },
  },
  resolve: {
    ...sharedConfig.resolve,
    alias: {
      ...sharedConfig.resolve?.alias,
      '@ui-public-config': resolve(configDir, './src/variants/publicConfig.application.js'),
      '@ui-public-routes': resolve(configDir, './src/variants/publicSite.application.jsx'),
    },
  },
})
