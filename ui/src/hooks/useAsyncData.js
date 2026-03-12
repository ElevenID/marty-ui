import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * useAsyncData — centralized async data fetching with loading/error state.
 *
 * Eliminates the recurring pattern:
 *   const [data, setData] = useState(null);
 *   const [loading, setLoading] = useState(true);
 *   const [error, setError] = useState(null);
 *   useEffect(() => { fetchFn().then(setData).catch(setError).finally(...) }, [...]);
 *
 * @example
 *   const { data: roles, loading, error, reload } = useAsyncData(
 *     () => listRoles(organizationId),
 *     [organizationId]
 *   );
 *
 * @param {() => Promise<any>} fetchFn - Async function that returns the data.
 *   Re-created on every render that changes `deps`, so keep it stable or
 *   wrap it in useCallback when needed.
 * @param {any[]} [deps=[]] - Dependency array (same semantics as useEffect).
 *   The fetch is re-triggered whenever any dependency changes.
 * @returns {{ data: any, loading: boolean, error: Error|null, reload: () => Promise<void> }}
 */
export function useAsyncData(fetchFn, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Track whether the component is still mounted to avoid state updates on
  // unmounted components (e.g., when navigating away before the fetch resolves).
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchFn();
      if (mountedRef.current) setData(result);
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, deps); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    reload();
  }, [reload]);

  return { data, loading, error, reload };
}

export default useAsyncData;
