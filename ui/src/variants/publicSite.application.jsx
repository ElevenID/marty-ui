import BrowserRedirect from '../components/BrowserRedirect';
import { useAuth } from '../hooks/useAuth';
import { renderCommerceApplicationRoutes } from '../extensions/commerce';

export function renderPublicRoot() { return <BrowserRedirect to="/login" message="Opening application..." />; }
export function getPublicLoginFallback() { return '/'; }
export function renderMarketingRoutes({ login }) {
  return renderCommerceApplicationRoutes({ login, useAuth,
    checkoutBasePath: '/pricing/checkout', setupPath: '/console/org/setup', billingPath: '/console/org/billing' });
}
