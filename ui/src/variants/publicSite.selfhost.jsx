import { Navigate } from 'react-router';
import BrowserRedirect from '../components/BrowserRedirect';
import { publicEntryHref } from '../application/routing/publicEntry';
import { isWebSectionEnabled } from '../utils/runtimeConfig';

// Customer bundles deliberately do not import the production public-site
// module. Hiding its navigation would still ship the marketing page chunks.
export function getPublicLoginFallback() {
  return isWebSectionEnabled('console') ? '/console' : '/organizations';
}

export function renderPublicRoot({ isAuthenticated = false } = {}) {
  const destination = isAuthenticated ? getPublicLoginFallback() : '/login';
  const entryDestination = publicEntryHref(destination);

  // The console has its own HTML entrypoint; IP entry aliases must also hand
  // authentication to the configured DNS origin before checking the session.
  if (destination === '/console' || entryDestination !== destination) {
    return <BrowserRedirect to={entryDestination} message="Opening application..." />;
  }

  return <Navigate to={destination} replace />;
}

export function renderMarketingRoutes() {
  return null;
}
