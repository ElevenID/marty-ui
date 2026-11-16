const EMPTY_RUNTIME_CONFIG = Object.freeze({});
const ALL_WEB_SECTIONS = Object.freeze(['public', 'console']);
const NO_WEB_SECTIONS = Object.freeze([]);
const CONSOLE_HANDOFF_PATHS = new Set([
  '/credentials', '/catalog', '/my-applications', '/my-documents',
]);

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

export function getHostingRuntimeConfig() {
  return getWindowRuntimeConfig().hosting;
}

export function isOrganizationCreationEnabled(legacyDefault = false) {
  const runtimeConfig = getWindowRuntimeConfig();
  if (Object.prototype.hasOwnProperty.call(runtimeConfig, 'organizationCreationEnabled')) {
    return runtimeConfig.organizationCreationEnabled === true;
  }
  return legacyDefault === true;
}

export function getEnabledWebSections() {
  const runtimeConfig = getWindowRuntimeConfig();
  if (!Object.prototype.hasOwnProperty.call(runtimeConfig, 'web')) {
    return ALL_WEB_SECTIONS;
  }

  const web = runtimeConfig.web;
  const sections = web && typeof web === 'object' && !Array.isArray(web)
    ? web.enabled_sections : null;
  if (!Array.isArray(sections)
    || sections.some((section) => !ALL_WEB_SECTIONS.includes(section))
    || new Set(sections).size !== sections.length) {
    return NO_WEB_SECTIONS;
  }
  return sections;
}

export function isWebSectionEnabled(section) {
  return getEnabledWebSections().includes(section);
}

export function isWebPathEnabled(pathname = '/') {
  const path = pathname.split(/[?#]/, 1)[0];
  // Authentication callbacks are shared by the two application entrypoints.
  if (path === '/auth/callback') return getEnabledWebSections().length > 0;
  // Public apply links authenticate here and then open the applicant console.
  if (path === '/apply' || path.startsWith('/apply/')) {
    return isWebSectionEnabled('public') && isWebSectionEnabled('console');
  }
  const consolePath = path === '/console' || path.startsWith('/console/')
    || path.startsWith('/console-handoff/') || CONSOLE_HANDOFF_PATHS.has(path);
  return isWebSectionEnabled(consolePath ? 'console' : 'public');
}

export function getGoogleAnalyticsMeasurementId() {
  const runtimeConfig = getWindowRuntimeConfig();
  if (Object.prototype.hasOwnProperty.call(runtimeConfig, 'googleAnalyticsMeasurementId')) {
    const runtimeValue = runtimeConfig.googleAnalyticsMeasurementId;
    return typeof runtimeValue === 'string' ? runtimeValue.trim() : '';
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
