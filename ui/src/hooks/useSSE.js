import { useEffect, useRef } from 'react';
import sseService from '../services/sseService';

/**
 * useSSE — Manages SSE connection lifecycle tied to a React component.
 *
 * Automatically connects on mount and disconnects when the component
 * unmounts (or when organizationId changes).
 *
 * @param {string|null} organizationId - Organization to subscribe to
 * @param {string|null} userId - Optional user filter
 * @param {string[]} [subscriptions] - Optional event type filters
 */
export function useSSE(organizationId, userId = null, subscriptions = undefined) {
  const connectedRef = useRef(false);

  useEffect(() => {
    if (!organizationId) return;

    // Avoid duplicate connections
    if (sseService.isActive()) return;

    sseService.connect({
      organizationId,
      userId,
      subscriptions,
    });
    connectedRef.current = true;

    return () => {
      if (connectedRef.current) {
        sseService.disconnect();
        connectedRef.current = false;
      }
    };
  }, [organizationId, userId]);

  return { isConnected: sseService.isActive() };
}

export default useSSE;
