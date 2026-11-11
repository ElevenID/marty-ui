import type { StorybookConfig } from '@storybook/react-vite'

const config: StorybookConfig = {
  stories: ['../src/**/*.mdx', '../src/**/*.stories.@(js|jsx|mjs|ts|tsx)'],
  addons: [],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  docs: {
    autodocs: 'tag',
  },
  staticDirs: ['../public', './public'],
  async viteFinal(config) {
    // Customize the Vite config here
    return {
      ...config,
      // Storybook has its own output directory and does not publish site crawlers.
      plugins: config.plugins?.filter((plugin) => !(
        plugin && typeof plugin === 'object' && 'name' in plugin
        && plugin.name === 'vite-plugin-sitemap'
      )),
      resolve: {
        ...config.resolve,
        alias: {
          ...config.resolve?.alias,
          '@': '/src',
          '@components': '/src/components',
          '@services': '/src/services',
          '@hooks': '/src/hooks',
          '@contexts': '/src/contexts',
          '@config': '/src/config',
          '@test': '/src/test',
        },
      },
    }
  },
}

export default config
