import { Navigate } from 'react-router-dom';
import BrowserRedirect from '../components/BrowserRedirect';
import {
  renderMarketingRoutes as renderOriginalMarketingRoutes,
  renderPublicRoot as renderOriginalPublicRoot,
} from './publicSite.public';

function getSelfhostRootPath({ isAuthenticated, isAdministrator, isVendor, isApplicant }) {
  if (isAdministrator || isVendor) {
    return '/console/org';
  }

  if (isApplicant) {
    return '/console/applicant/catalog';
  }

  return '/login';
}

export function renderPublicRoot(authState) {
  if (!authState?.isAuthenticated) {
    return renderOriginalPublicRoot();
  }

  const destination = getSelfhostRootPath(authState);

  if (destination.startsWith('/console')) {
    return <BrowserRedirect to={destination} />;
  }

  return <Navigate to={destination} replace />;
}

export function renderMarketingRoutes(options) {
  return renderOriginalMarketingRoutes(options);
}