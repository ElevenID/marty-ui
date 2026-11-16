import { getHostingRuntimeConfig } from '../../utils/runtimeConfig';

function httpsOrigin(value) {
  if (typeof value !== 'string' || value.length > 320) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value
      && url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password
      ? url : null;
  } catch {
    return null;
  }
}

function isIpLiteral(hostname) {
  return hostname.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
}

/**
 * Only installer-supplied runtime configuration can select public-entry mode.
 * This controls browser behavior; the edge independently enforces the allowed
 * Host and static routes. Hostnames, query parameters and forwarded headers
 * never discover or replace the configured identity.
 */
export function getPublicEntryCanonicalOrigin(
  currentOrigin = typeof window === 'undefined' ? '' : window.location.origin,
  configuration = getHostingRuntimeConfig(),
) {
  if (!configuration || typeof configuration !== 'object') return null;
  const canonical = httpsOrigin(configuration.canonicalOrigin);
  const aliases = configuration.publicEntryOrigins;
  if (!canonical || isIpLiteral(canonical.hostname) || canonical.hostname === 'localhost'
    || !Array.isArray(aliases) || aliases.length !== 1) return null;
  const alias = httpsOrigin(aliases[0]);
  if (!alias || !isIpLiteral(alias.hostname) || alias.origin !== currentOrigin) return null;
  return canonical.origin;
}

/** Keep local fragments on the entry page; interactive navigation uses DNS. */
export function publicEntryHref(destination) {
  const canonical = getPublicEntryCanonicalOrigin();
  if (!canonical || typeof destination !== 'string' || !destination || destination.startsWith('#')) {
    return destination;
  }
  try {
    const resolved = new URL(destination, window.location.href);
    if (resolved.origin === window.location.origin) {
      return `${canonical}${resolved.pathname}${resolved.search}${resolved.hash}`;
    }
  } catch {
    // Preserve the existing navigation contract outside recognized local URLs.
  }
  return destination;
}
