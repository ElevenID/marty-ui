import { useCallback, useLayoutEffect, useMemo, useState } from 'react';

/** Retain the committed entry while a newer router destination is suspended. */
export function useBrowserEntry(location, { matchReturnByRouteKey = false } = {}) {
  const [generation, setGeneration] = useState(0);
  const { key, pathname, search, hash } = location;
  // Exact-entry pages reset their listener only when route coordinates change;
  // flow pages historically also reset it when the location object changes.
  const returnScope = matchReturnByRouteKey ? location : null;
  const entry = useMemo(() => ({
    href: typeof window === 'undefined' ? null : window.location.href,
    key: typeof window === 'undefined' ? undefined : window.history.state?.key,
    routeKey: location.key,
    generation,
  }), [location, generation]);

  useLayoutEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const captured = { href: window.location.href, key: window.history.state?.key };
    const handlePopState = () => {
      const returned = matchReturnByRouteKey
        ? (window.history.state?.key || 'default') === key
        : window.location.href === captured.href && window.history.state?.key === captured.key;
      if (returned) setGeneration((value) => value + 1);
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [key, pathname, search, hash, returnScope, matchReturnByRouteKey]);

  return entry;
}

export function useIsCurrentBrowserEntry(entry) {
  return useCallback(() => entry.href === null || (
    typeof window !== 'undefined' && window.location.href === entry.href
      && window.history.state?.key === entry.key
      && (entry.key || 'default') === entry.routeKey
  ), [entry]);
}
