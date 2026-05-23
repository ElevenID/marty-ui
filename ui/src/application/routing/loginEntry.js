/**
 * Pure helpers for the /login route.
 */

export function getLoginEntryRedirect(locationState, fallback = '/', search = '') {
  const statePath = locationState?.from?.pathname;
  const stateSearch = locationState?.from?.search || '';
  if (statePath) {
    return `${statePath}${stateSearch}`;
  }

  const next = new URLSearchParams(search || '').get('next');
  return next || fallback;
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
