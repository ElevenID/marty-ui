/**
 * Health API Service
 * 
 * Provides system health status for:
 * - API Gateway
 * - Issuer Metadata Service
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
export async function getSystemHealth() {
  try {
    const response = await fetch('/health', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      return {
        gateway: HealthStatus.ERROR,
        issuer: HealthStatus.UNKNOWN,
        verifier: HealthStatus.UNKNOWN,
      };
    }

    const data = await response.json();

    // Map backend health response to UI health statuses
    // Backend may return: { status: "healthy" | "degraded" | "unhealthy", services: {...} }
    return parseHealthResponse(data);
  } catch (error) {
    console.error('Health check failed:', error);
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
  // Default to healthy if no specific service data
  const defaultStatus = data.status === 'healthy' 
    ? HealthStatus.HEALTHY 
    : data.status === 'degraded'
    ? HealthStatus.WARNING
    : data.status === 'unhealthy'
    ? HealthStatus.ERROR
    : HealthStatus.UNKNOWN;

  // If backend provides detailed service health
  const services = data.services || {};

  return {
    gateway: mapServiceHealth(services.gateway || services.api || defaultStatus),
    issuer: mapServiceHealth(services.issuer || services.issuer_metadata || defaultStatus),
    verifier: mapServiceHealth(services.verifier || services.verifier_service || defaultStatus),
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
      case 'up':
      case 'ok':
        return HealthStatus.HEALTHY;
      case 'degraded':
      case 'warning':
        return HealthStatus.WARNING;
      case 'unhealthy':
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
