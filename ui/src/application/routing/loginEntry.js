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

  const next = new URLSearchParams(search || '').get('next');
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
