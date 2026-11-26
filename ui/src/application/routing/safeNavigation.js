import { getPublicEntryCanonicalOrigin } from './publicEntry';
import { hasAsciiControlCharacters } from '../../utils/hasAsciiControlCharacters.js';

/** Bound application redirects to this origin or its configured entry alias. */
export function safeNavigationDestination(destination, location = typeof window === 'undefined' ? null : window.location) {
  if (typeof destination !== 'string' || !destination || destination !== destination.trim()
    || destination.startsWith('//') || destination.includes('\\')
    || hasAsciiControlCharacters(destination)) return null;
  try {
    const current = new URL(location?.href || 'https://marty.invalid/');
    const resolved = new URL(destination, current);
    if (!['http:', 'https:'].includes(resolved.protocol) || resolved.username || resolved.password) return null;
    if (resolved.origin === current.origin) return `${resolved.pathname}${resolved.search}${resolved.hash}`;
    const canonical = getPublicEntryCanonicalOrigin(current.origin);
    return canonical && resolved.origin === canonical ? resolved.href : null;
  } catch {
    return null;
  }
}

/** Organization onboarding can resume only a console page on this origin. */
export function safeConsoleNavigationDestination(destination, location) {
  const safe = safeNavigationDestination(destination, location);
  const pathname = safe?.split(/[?#]/, 1)[0];
  if (!pathname || (pathname !== '/console' && !pathname.startsWith('/console/'))) return null;
  try {
    // The router decodes path segments before matching the setup route.
    if (/^\/console\/org\/setup\/*$/i.test(decodeURIComponent(pathname))) return null;
  } catch {
    return null;
  }
  return safe;
}
