import type { StorybookConfig } from '@storybook/react-vite'

const config: StorybookConfig = {
  stories: ['../src/**/*.mdx', '../src/**/*.stories.@(js|jsx|mjs|ts|tsx)'],
  addons: [
    '@storybook/addon-links',
    '@storybook/addon-essentials',
    '@storybook/addon-interactions',
  ],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  docs: {
    autodocs: 'tag',
  },
  staticDirs: ['../public'],
  async viteFinal(config) {
    // Customize the Vite config here
    return {
      ...config,
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
