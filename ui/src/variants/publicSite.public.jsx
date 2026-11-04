import { lazy } from 'react';
import { DISABLE_PUBLIC_GET_STARTED_BUTTONS } from '@ui-public-config';
import { useAuth } from '../hooks/useAuth';
import { renderCommercePublicRoutes } from '../extensions/commerce';
import { renderWebsiteContentRoutes } from './marketingRoutes';

const LandingPage = lazy(() => import('../components/LandingPage'));
export function renderPublicRoot() { return <LandingPage />; }
export function getPublicLoginFallback() { return '/'; }
export function renderMarketingRoutes({ login, showDemos = true }) {
  return <>
    {renderWebsiteContentRoutes({ showDemos })}
    {renderCommercePublicRoutes({ login, useAuth,
      disableSandboxSignup: DISABLE_PUBLIC_GET_STARTED_BUTTONS,
      checkoutBasePath: '/pricing/checkout', setupPath: '/console/org/setup', billingPath: '/console/org/billing' })}
  </>;
}
