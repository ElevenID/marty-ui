import { get } from '../../services/api';
import {
  METRICS_VIEWER_DEFAULT_METRICS,
  resolveMetricsViewerMetrics,
} from './metricsFlow';

async function defaultGetAdminMetrics() {
  return get('/api/admin/metrics');
}

export async function loadAdminMetrics({
  getAdminMetrics = defaultGetAdminMetrics,
} = {}) {
  try {
    const result = await getAdminMetrics();
    return resolveMetricsViewerMetrics(result, METRICS_VIEWER_DEFAULT_METRICS);
  } catch (error) {
    console.error('Failed to fetch metrics:', error);
    return METRICS_VIEWER_DEFAULT_METRICS;
  }
}
