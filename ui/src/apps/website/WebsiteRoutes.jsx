import { Route, Routes, useLocation } from 'react-router';
import { DISABLE_PUBLIC_GET_STARTED_BUTTONS } from '@ui-public-config';
import LandingPageContent from '../../components/LandingPageContent';
import WebSectionUnavailable from '../../components/WebSectionUnavailable';
import { renderWebsiteContentRoutes } from '../../variants/marketingRoutes';
import { renderCommerceWebsiteRoutes } from '../../extensions/commerce/website';
import { isWebPathEnabled, isWebSectionEnabled } from '../../utils/runtimeConfig';
import { useSurfaceNavigate } from '../../application/routing/useSurfaceNavigate';

export default function WebsiteRoutes() {
  const location = useLocation();
  const navigate = useSurfaceNavigate();
  if (!isWebSectionEnabled('public') || !isWebPathEnabled(location.pathname)) return <WebSectionUnavailable />;
  return <Routes>
    <Route path="/" element={<LandingPageContent />} />
    {renderWebsiteContentRoutes()}
    {renderCommerceWebsiteRoutes({ navigate,
      login: () => navigate('/login?next=%2Fconsole%2Forg%2Fsetup'),
      disableSandboxSignup: DISABLE_PUBLIC_GET_STARTED_BUTTONS,
      checkoutBasePath: '/pricing/checkout' })}
    <Route path="*" element={<WebSectionUnavailable />} />
  </Routes>;
}
