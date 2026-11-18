import { useCallback, useLayoutEffect, useRef } from 'react';

/** Keep a view's async follow-ups within its mounted lifetime and latest action. */
export function useAsyncActionScope() {
  const mounted = useRef(false);
  const generation = useRef(0);

  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);

  return useCallback(() => {
    const actionGeneration = ++generation.current;
    const isCurrent = () => mounted.current && generation.current === actionGeneration;
    const assertCurrent = () => {
      if (!isCurrent()) {
        const error = new Error('The view or action changed.');
        error.name = 'AbortError';
        throw error;
      }
    };
    return {
      isCurrent,
      async run(operation, ...args) {
        assertCurrent();
        try {
          return await operation(...args);
        } finally {
          assertCurrent();
        }
      },
    };
  }, []);
}
