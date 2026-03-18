/**
 * Pure helpers for the metrics viewer.
 */

export const METRICS_VIEWER_CHART_FALLBACK = [
  { name: '00:00', issuance: 4, verification: 2 },
  { name: '04:00', issuance: 3, verification: 1 },
  { name: '08:00', issuance: 15, verification: 8 },
  { name: '12:00', issuance: 45, verification: 23 },
  { name: '16:00', issuance: 38, verification: 30 },
  { name: '20:00', issuance: 12, verification: 15 },
  { name: '23:59', issuance: 5, verification: 4 },
];

export const METRICS_VIEWER_DEFAULT_METRICS = {
  cpu_usage: 0,
  memory_usage: 0,
  request_rate: 0,
  transaction_volume: METRICS_VIEWER_CHART_FALLBACK,
};

export function resolveMetricsViewerMetrics(data, fallback = METRICS_VIEWER_DEFAULT_METRICS) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    ...fallback,
    ...data,
    transaction_volume: Array.isArray(data.transaction_volume)
      ? data.transaction_volume
      : fallback.transaction_volume,
  };
}

export function getMetricsViewerRequestRateProgress(requestRate = 0, maxRate = 100) {
  if (!Number.isFinite(requestRate) || requestRate <= 0) {
    return 0;
  }

  return Math.min(100, Math.round((requestRate / maxRate) * 100));
}
