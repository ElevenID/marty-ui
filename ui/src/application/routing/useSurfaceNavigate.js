import { useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { redirectBrowser, shouldBrowserRedirect } from './appHandoff';
import { safeNavigationDestination } from './safeNavigation';
import { publicEntryHref } from './publicEntry';

/** A route change must load the receiving document when crossing surfaces. */
export function useSurfaceNavigate() {
  const navigate = useNavigate();
  const location = useLocation();
  return useCallback((destination, options) => {
    if (typeof destination === 'number') return navigate(destination);
    const value = typeof destination === 'string' ? destination
      : `${destination?.pathname || location.pathname}${destination?.search || ''}${destination?.hash || ''}`;
    const safe = safeNavigationDestination(value);
    if (!safe) return false;
    if (publicEntryHref(safe) !== safe || shouldBrowserRedirect({ currentPathname: location.pathname, destination: value })) {
      return redirectBrowser(safe, { replace: Boolean(options?.replace) });
    }
    return options === undefined ? navigate(safe) : navigate(safe, options);
  }, [navigate, location.pathname]);
}
