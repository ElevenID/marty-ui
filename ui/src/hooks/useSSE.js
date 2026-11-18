import { useEffect } from 'react';
import sseService from '../services/sseService';

/**
 * useSSE — Manages SSE connection lifecycle tied to a React component.
 *
 * Automatically connects on mount and disconnects when the component
 * unmounts (or when organizationId changes).
 *
 * @param {string|null} organizationId - Organization to subscribe to
 * @param {string|null} userId - Optional authenticated account scope
 * @param {string[]} [subscriptions] - Optional event type filters
 */
export function useSSE(organizationId, userId = null, subscriptions = undefined) {
  const subscriptionKey = JSON.stringify(subscriptions || []);

  useEffect(() => {
    if (!organizationId) return;

    sseService.connect({
      organizationId,
      userId,
      subscriptions: JSON.parse(subscriptionKey),
    });

    return () => sseService.disconnect();
  }, [organizationId, userId, subscriptionKey]);

  return { isConnected: sseService.isActive() };
}

export default useSSE;
