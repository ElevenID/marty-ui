import { publicEntryHref } from './publicEntry';
import { safeNavigationDestination } from './safeNavigation';
import { getWebSurface } from './webSurface';

const CONSOLE_PREFIX = '/console';

export function isConsolePath(pathname = '') {
  return pathname === CONSOLE_PREFIX || pathname.startsWith(`${CONSOLE_PREFIX}/`);
}

export function shouldBrowserRedirect({ currentPathname = '', destination = '', surface }) {
  const safe = safeNavigationDestination(destination);
  if (!safe || destination.startsWith('#')) return false;
  const target = new URL(safe, typeof window === 'undefined' ? 'https://marty.invalid/' : window.location.href);
  const current = surface === 'website' || surface === 'application' ? surface : getWebSurface(currentPathname);
  return getWebSurface(target.pathname) !== current
    || (isConsolePath(target.pathname) !== isConsolePath(currentPathname));
}

function resolveDestinationUrl(destination, location) {
  try {
    return new URL(destination, location?.href || window.location.href);
  } catch {
    return null;
  }
}

function isSameLocationDestination(destination, location) {
  if (!destination || !location) {
    return false;
  }

  const resolved = resolveDestinationUrl(destination, location);
  if (!resolved) {
    return false;
  }

  const currentHref = location.href || `${location.origin || ''}${location.pathname || ''}${location.search || ''}${location.hash || ''}`;
  return resolved.href === currentHref;
}

export function redirectBrowser(destination, { replace = true, location = window.location } = {}) {
  const safe = safeNavigationDestination(destination, location);
  if (!safe) {
    return false;
  }
  destination = publicEntryHref(destination.startsWith('#') ? destination : safe);

  // Guard against no-op redirects that can cause hard-refresh loops.
  if (isSameLocationDestination(destination, location)) {
    return false;
  }

  if (replace && typeof location.replace === 'function') {
    location.replace(destination);
    return true;
  }

  if (typeof location.assign === 'function') {
    location.assign(destination);
    return true;
  }

  location.href = destination;
  return true;
}
