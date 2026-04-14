const EMPTY_RUNTIME_CONFIG = Object.freeze({});

function getWindowRuntimeConfig() {
  if (typeof window === 'undefined') {
    return EMPTY_RUNTIME_CONFIG;
  }

  const runtimeConfig = window.__MARTY_RUNTIME_CONFIG__;
  if (!runtimeConfig || typeof runtimeConfig !== 'object') {
    return EMPTY_RUNTIME_CONFIG;
  }

  return runtimeConfig;
}

export function getGoogleAnalyticsMeasurementId() {
  const runtimeValue = getWindowRuntimeConfig().googleAnalyticsMeasurementId;
  if (typeof runtimeValue === 'string' && runtimeValue.trim()) {
    return runtimeValue.trim();
  }

  const buildValue = import.meta.env.VITE_GA_MEASUREMENT_ID;
  return typeof buildValue === 'string' ? buildValue.trim() : '';
}