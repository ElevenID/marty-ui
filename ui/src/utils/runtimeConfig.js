const EMPTY_RUNTIME_CONFIG = Object.freeze({});

function normalizeBooleanFlag(value) {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    return value !== 0;
  }

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (!normalized) {
      return null;
    }

    if (['1', 'true', 'yes', 'on', 'enabled'].includes(normalized)) {
      return true;
    }

    if (['0', 'false', 'no', 'off', 'disabled'].includes(normalized)) {
      return false;
    }
  }

  return null;
}

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

export function isAdminImpersonationEnabled() {
  const runtimeFlag = normalizeBooleanFlag(getWindowRuntimeConfig().adminImpersonationEnabled);
  if (runtimeFlag !== null) {
    return runtimeFlag;
  }

  const buildFlag = normalizeBooleanFlag(import.meta.env.VITE_ENABLE_ADMIN_IMPERSONATION);
  if (buildFlag !== null) {
    return buildFlag;
  }

  // Safe default: disabled in production unless explicitly enabled.
  return import.meta.env.PROD !== true;
}