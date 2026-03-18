/**
 * Pure helpers for the /login route.
 */

export function getLoginEntryRedirect(locationState, fallback = '/') {
  return locationState?.from?.pathname || fallback;
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