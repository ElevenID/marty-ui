/**
 * Pure helpers for the public landing page entry flow.
 */

export function getLandingAuthError(searchParams) {
  const error = searchParams?.get?.('auth_error');
  if (!error) {
    return null;
  }

  return decodeURIComponent(error.replace(/\+/g, ' '));
}

export function clearLandingAuthError(searchParams) {
  const nextParams = new URLSearchParams(searchParams?.toString?.() || '');
  nextParams.delete('auth_error');
  return nextParams;
}

export function getLandingEntryDecision({ isAuthenticated, isLoading, redirectTo = '/console/applicant' }) {
  if (isLoading) {
    return {
      action: 'loading',
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
    action: 'render',
    redirectTo: null,
  };
}