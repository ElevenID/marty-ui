import type { Preview } from '@storybook/react'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import { BrowserRouter } from 'react-router-dom'
import { initialize, mswLoader } from 'msw-storybook-addon'
import { handlers } from '../src/test/mocks/handlers'

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
      <BrowserRouter>
        <ThemeProvider theme={theme}>
          <CssBaseline />
          <div style={{ padding: '2rem' }}>
            <Story />
          </div>
        </ThemeProvider>
      </BrowserRouter>
    ),
  ],
  loaders: [mswLoader],
}

export default preview
