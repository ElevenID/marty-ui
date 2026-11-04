import { getPublicEntryCanonicalOrigin } from './publicEntry';

/** Bound application redirects to this origin or its configured entry alias. */
export function safeNavigationDestination(destination, location = typeof window === 'undefined' ? null : window.location) {
  if (typeof destination !== 'string' || !destination || destination !== destination.trim()
    || destination.startsWith('//') || /[\u0000-\u001f\u007f\\]/u.test(destination)) return null;
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
