import type { Preview } from '@storybook/react'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import { BrowserRouter } from 'react-router-dom'
import { I18nextProvider } from 'react-i18next'
import { initialize, mswLoader } from 'msw-storybook-addon'
import { handlers } from '../src/test/mocks/handlers'
import i18n from '../src/test/i18nTestSetup'

// Initialize MSW for Storybook
initialize({
  onUnhandledRequest: 'bypass',
})

// Create MUI theme (match your app's theme)
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
})

const preview: Preview = {
  parameters: {
    actions: { argTypesRegex: '^on[A-Z].*' },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    msw: {
      handlers: handlers,
    },
  },
  decorators: [
    (Story) => (
      <I18nextProvider i18n={i18n}>
        <BrowserRouter>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            <div style={{ padding: '2rem' }}>
              <Story />
            </div>
          </ThemeProvider>
        </BrowserRouter>
      </I18nextProvider>
    ),
  ],
  loaders: [mswLoader],
}

export default preview
