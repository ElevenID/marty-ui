/**
 * Pure helpers for the /login route.
 */
import { safeNavigationDestination } from './safeNavigation';

export function getLoginEntryRedirect(locationState, fallback = '/', search = '') {
  const statePath = locationState?.from?.pathname;
  const stateSearch = locationState?.from?.search || '';
  const stateHash = locationState?.from?.hash || '';
  if (statePath) {
    const stateDestination = safeNavigationDestination(`${statePath}${stateSearch}${stateHash}`);
    if (stateDestination) return stateDestination;
  }

  const params = new URLSearchParams(search || '');
  // Existing /apply entry links use return_to. Validate that destination just
  // like next so sign-in does not discard the selected credential or org.
  const next = params.get('next') ?? params.get('return_to');
  return safeNavigationDestination(next) || safeNavigationDestination(fallback) || '/';
}

export function getLoginEntryDecision({ isAuthenticated, isLoading, redirectTo = '/' }) {
  if (isLoading) {
    return {
      action: 'idle',
      redirectTo: null,
    };
  }

  if (isAuthenticated) {
    return {
      action: 'navigate',
      redirectTo,
    };
  }

  return {
    action: 'login',
    redirectTo: null,
  };
}
