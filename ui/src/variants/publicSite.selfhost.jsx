import { Navigate } from 'react-router-dom';
import {
  renderMarketingRoutes as renderOriginalMarketingRoutes,
  renderPublicRoot as renderOriginalPublicRoot,
} from './publicSite.public';

function getSelfhostRootPath({ isAuthenticated, isAdministrator, isVendor, isApplicant }) {
  if (isAdministrator) {
    return '/dashboard';
  }

  if (isVendor) {
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

  return <Navigate to={getSelfhostRootPath(authState)} replace />;
}

export function renderMarketingRoutes(options) {
  return renderOriginalMarketingRoutes(options);
}