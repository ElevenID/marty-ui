import {
  getPublicLoginFallback as getOriginalPublicLoginFallback,
  renderMarketingRoutes as renderOriginalMarketingRoutes,
  renderPublicRoot as renderOriginalPublicRoot,
} from './publicSite.public';
import { SHOW_PUBLIC_DEMOS } from './publicConfig.selfhost';

export function getPublicLoginFallback() {
  return getOriginalPublicLoginFallback();
}

export function renderPublicRoot(authState) {
  return renderOriginalPublicRoot(authState);
}

export function renderMarketingRoutes(options) {
  return renderOriginalMarketingRoutes({ ...options, showDemos: SHOW_PUBLIC_DEMOS });
}
