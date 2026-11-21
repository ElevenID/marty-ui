import BrowserRedirect from '../components/BrowserRedirect';
import { useAuth } from '../hooks/useAuth';
import { renderCommerceApplicationRoutes } from '../extensions/commerce';
import { isWebSectionEnabled } from '../utils/runtimeConfig';

export function renderPublicRoot() { return <BrowserRedirect to="/login" message="Opening application..." />; }
export function getPublicLoginFallback() {
  // The independent website root no longer resolves an authenticated session
  // into the console. Keep the default sign-in destination in the application.
  return isWebSectionEnabled('console') ? '/console' : '/organizations';
}
export function renderMarketingRoutes({ login }) {
  return renderCommerceApplicationRoutes({ login, useAuth,
    checkoutBasePath: '/pricing/checkout', setupPath: '/console/org/setup', billingPath: '/console/org/billing' });
}
