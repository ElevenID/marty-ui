import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useAuth } from '../hooks/useAuth';
import { getLandingEntryDecision } from '../application/routing/landingEntry';
import { redirectBrowser, shouldBrowserRedirect } from '../application/routing/appHandoff';
import LandingPageContent from './LandingPageContent';

// The combined migration entry retains authenticated-home routing. The independent
// website imports content directly and never checks a product session.
export default function LandingPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  useEffect(() => {
    const decision = getLandingEntryDecision({ isAuthenticated, isLoading });
    if (decision.action !== 'navigate' || !decision.redirectTo) return;
    if (shouldBrowserRedirect({ currentPathname: location.pathname, destination: decision.redirectTo })) {
      redirectBrowser(decision.redirectTo);
    } else navigate(decision.redirectTo, { replace: true });
  }, [isAuthenticated, isLoading, location.pathname, navigate]);
  return <LandingPageContent isLoading={isLoading} />;
}
