module.exports = {
  root: true,
  env: {
    browser: true,
    es2020: true,
  },
  extends: [
    'eslint:recommended',
    'plugin:react/recommended',
    'plugin:react/jsx-runtime',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', 'build', '.eslintrc.cjs'],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  settings: {
    react: {
      version: '18.2',
    },
  },
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
    // Relax rules for existing codebase
    'react/prop-types': 'off',
    'no-unused-vars': 'warn', // Warn instead of error
    'no-undef': 'error', // Keep this as error since it's critical
    'react/no-unescaped-entities': 'warn', // Warn for HTML entities
    'react-hooks/exhaustive-deps': 'warn', // Warn for missing dependencies
  },
  overrides: [
    {
      // Config files run in Node.js, not browser
      files: ['vite.config.ts', '*.config.js', '*.config.ts'],
      env: {
        node: true,
      },
    },
  ],
}
