/**
 * Health API Service
 * 
 * Provides system health status for:
 * - API Gateway
 * - Issuance Service
 * - Verifier Service
 */

/**
 * Health status levels
 */
export const HealthStatus = {
  HEALTHY: 'healthy',
  WARNING: 'warning',
  ERROR: 'error',
  UNKNOWN: 'unknown',
};

/**
 * Get system health status
 * @returns {Promise<Object>} Health status for all services
 */
export async function getSystemHealth({ signal } = {}) {
  try {
    // The liveness endpoint only describes the gateway process. Readiness
    // includes the individual services that the gateway actually checked.
    const response = await fetch('/health/ready', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      cache: 'no-store',
      signal,
    });

    // A native 503 still contains useful per-service observations. Preserve
    // those without presenting the unavailable gateway as ready.
    const data = await response.json().catch(() => null);
    const health = parseHealthResponse(data);
    return response.ok ? health : { ...health, gateway: HealthStatus.ERROR };
  } catch {
    return {
      gateway: HealthStatus.ERROR,
      issuer: HealthStatus.UNKNOWN,
      verifier: HealthStatus.UNKNOWN,
    };
  }
}

/**
 * Parse backend health response into UI health statuses
 * @param {Object} data - Backend health response
 * @returns {Object} Parsed health statuses
 */
function parseHealthResponse(data) {
  const response = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
  const services = response.services && typeof response.services === 'object'
    && !Array.isArray(response.services) ? response.services : {};

  // Never infer an unreported service's health from the gateway's aggregate.
  // `issuer` remains the dashboard's compatibility field for the issuance
  // service, whose native registry name is `issuance-native` or `issuance`.
  return {
    gateway: mapServiceHealth(services.gateway ?? services.api ?? response.status),
    issuer: mapServiceHealth(services['issuance-native'] ?? services.issuance),
    verifier: mapServiceHealth(services.verification ?? services.verifier ?? services.verifier_service),
  };
}

/**
 * Map individual service health to UI status
 * @param {string|Object} serviceHealth - Service health data
 * @returns {string} UI health status
 */
function mapServiceHealth(serviceHealth) {
  if (typeof serviceHealth === 'string') {
    switch (serviceHealth.toLowerCase()) {
      case 'healthy':
      case 'ready':
      case 'up':
      case 'ok':
        return HealthStatus.HEALTHY;
      case 'degraded':
      case 'warning':
        return HealthStatus.WARNING;
      case 'unhealthy':
      case 'not_ready':
      case 'unreachable':
      case 'down':
      case 'error':
        return HealthStatus.ERROR;
      default:
        return HealthStatus.UNKNOWN;
    }
  }

  if (typeof serviceHealth === 'object' && serviceHealth !== null) {
    const status = serviceHealth.status || serviceHealth.health;
    return mapServiceHealth(status);
  }

  return HealthStatus.UNKNOWN;
}
