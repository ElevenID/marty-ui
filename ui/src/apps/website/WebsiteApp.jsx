import { Component, Suspense, useEffect, useMemo } from 'react';
import { BrowserRouter, Link, useLocation } from 'react-router';
import { AppBar, Box, Button, Container, CssBaseline, Tabs, Tab, Toolbar, Typography } from '@mui/material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { useTranslation } from 'react-i18next';
import { BrandingProvider } from '../../contexts/BrandingContext';
import { useBranding } from '../../hooks/useBranding';
import LanguageSwitcher from '../../components/common/LanguageSwitcher';
import PublicFooter from '../../components/layouts/PublicFooter';
import { PUBLIC_TABS, SHOW_PUBLIC_LOGIN_BUTTON, DISABLE_PUBLIC_LOGIN_BUTTON, SHOW_PUBLIC_CTA } from '@ui-public-config';
import { publicEntryHref } from '../../application/routing/publicEntry';
import { isWebPathEnabled, isWebSectionEnabled } from '../../utils/runtimeConfig';
import { initAnalytics, trackPageView, trackWebVitals } from '../../utils/analytics';
import PrerenderReadySignal from '../shared/PrerenderReadySignal';
import WebSurfaceBoundary from '../shared/WebSurfaceBoundary';
import WebsiteRoutes from './WebsiteRoutes';

class WebsiteErrorBoundary extends Component {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <main><h1>This page could not be loaded.</h1><a href="/">Reload website</a></main> : this.props.children;
  }
}

function WebsiteShell() {
  const location = useLocation();
  const { t } = useTranslation('common');
  const { branding } = useBranding();
  const theme = useMemo(() => createTheme({ palette: {
    primary: { main: branding.primaryColor || '#1976d2' },
    secondary: { main: branding.secondaryColor || '#dc004e' },
  } }), [branding.primaryColor, branding.secondaryColor]);
  const tabs = PUBLIC_TABS.filter((tab) => isWebPathEnabled(tab.path));
  const selected = tabs.findIndex((tab) => tab.exact ? location.pathname === tab.path
    : (tab.prefixes || [tab.path]).some((prefix) => location.pathname.startsWith(prefix)));
  useEffect(() => { initAnalytics(); trackWebVitals(); }, []);
  useEffect(() => { trackPageView(`${location.pathname}${location.search}`, document.title); }, [location.pathname, location.search]);
  return <ThemeProvider theme={theme}>
    <CssBaseline />
    <WebSurfaceBoundary surface="website">
      <AppBar position="static"><Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>{branding.appName}</Typography>
        <LanguageSwitcher compact sx={{ mr: 2 }} />
        {SHOW_PUBLIC_LOGIN_BUTTON && <Button component="a" color="inherit" disabled={DISABLE_PUBLIC_LOGIN_BUTTON}
          href={publicEntryHref(`/login?next=${encodeURIComponent(isWebSectionEnabled('console') ? '/console' : '/organizations')}`)}>
          {t('common.login', 'Login')}
        </Button>}
      </Toolbar></AppBar>
      <Container maxWidth="lg">
        <Box sx={{ display: 'flex', alignItems: 'center', borderBottom: 1, borderColor: 'divider', my: 2 }}>
          <Tabs value={selected < 0 ? false : selected} variant="scrollable" scrollButtons="auto" aria-label="navigation" sx={{ flexGrow: 1 }}>
            {tabs.map((tab) => <Tab key={tab.path} label={t(tab.labelKey, tab.defaultLabel)} component={Link}
              to={publicEntryHref(tab.path)} disabled={Boolean(tab.disabled)} />)}
          </Tabs>
          {SHOW_PUBLIC_CTA && <Button component={Link} to={publicEntryHref('/verify')} sx={{ whiteSpace: 'nowrap', display: { xs: 'none', md: 'inline-flex' } }}>
            {t('navigation.startVerifying', 'Start Verifying')}
          </Button>}
        </Box>
        <WebsiteRoutes />
        <PublicFooter />
      </Container>
    </WebSurfaceBoundary>
  </ThemeProvider>;
}

export default function WebsiteApp() {
  return <WebsiteErrorBoundary><BrowserRouter>
    <PrerenderReadySignal />
    <Suspense fallback={<div data-app-loading>Loading...</div>}>
      <BrandingProvider><WebsiteShell /></BrandingProvider>
    </Suspense>
  </BrowserRouter></WebsiteErrorBoundary>;
}
