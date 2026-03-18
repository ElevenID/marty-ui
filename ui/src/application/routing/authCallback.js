import { get } from '../../services/api';

export function getAuthCallbackErrorFromParams(searchParams) {
  const errorParam = searchParams.get('error');
  const errorDescription = searchParams.get('error_description');

  if (!errorParam) {
    return null;
  }

  return errorDescription || errorParam;
}

export function getAuthCallbackCodeState(searchParams) {
  return {
    code: searchParams.get('code'),
    state: searchParams.get('state'),
  };
}

export function decodeAuthCallbackState(state, decode = atob) {
  if (!state) {
    return {};
  }

  try {
    return JSON.parse(decode(state));
  } catch {
    return {};
  }
}

export function resolveAuthCallbackRedirect({ state, consoleContext, getDefaultLandingPath, fallback = '/console/applicant/catalog' }) {
  const stateData = decodeAuthCallbackState(state);
  const returnTo = stateData.returnTo || '/';

  if (returnTo === '/') {
    return getDefaultLandingPath(consoleContext, fallback);
  }

  return returnTo;
}

export async function waitForAuthCallbackConsole({ consoleContext, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), maxAttempts = 30, delayMs = 100 }) {
  let attempts = 0;

  while (consoleContext.isLoading && attempts < maxAttempts) {
    await sleep(delayMs);
    attempts += 1;
  }

  return attempts;
}

export async function exchangeAuthCallbackCode({ code, state, exchangeAuthCallback = defaultExchangeAuthCallback }) {
  if (!code) {
    throw new Error('No authorization code received');
  }

  return exchangeAuthCallback({ code, state });
}

export async function completeAuthCallback({
  searchParams,
  refreshUser,
  consoleContext,
  getDefaultLandingPath,
  exchangeAuthCallback = defaultExchangeAuthCallback,
  sleep,
  fallback = '/console/applicant/catalog',
}) {
  const paramError = getAuthCallbackErrorFromParams(searchParams);
  if (paramError) {
    return {
      redirectTo: null,
      error: paramError,
    };
  }

  const { code, state } = getAuthCallbackCodeState(searchParams);

  try {
    await exchangeAuthCallbackCode({ code, state, exchangeAuthCallback });
    await refreshUser();
    await waitForAuthCallbackConsole({ consoleContext, sleep });

    return {
      redirectTo: resolveAuthCallbackRedirect({
        state,
        consoleContext,
        getDefaultLandingPath,
        fallback,
      }),
      error: null,
    };
  } catch (error) {
    return {
      redirectTo: null,
      error: error?.message || 'Authentication failed',
    };
  }
}

export async function defaultExchangeAuthCallback({ code, state }) {
  return get(`/v1/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state || '')}`);
}
