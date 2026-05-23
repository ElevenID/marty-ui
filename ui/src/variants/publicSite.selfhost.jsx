import {
  getPublicLoginFallback as getOriginalPublicLoginFallback,
  renderMarketingRoutes as renderOriginalMarketingRoutes,
  renderPublicRoot as renderOriginalPublicRoot,
} from './publicSite.public';

export function getPublicLoginFallback() {
  return getOriginalPublicLoginFallback();
}

export function renderPublicRoot(authState) {
  return renderOriginalPublicRoot(authState);
}

export function renderMarketingRoutes(options) {
  return renderOriginalMarketingRoutes(options);
}