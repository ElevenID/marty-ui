import { describe, expect, it } from 'vitest';

import {
  METRICS_VIEWER_CHART_FALLBACK,
  METRICS_VIEWER_DEFAULT_METRICS,
  getMetricsViewerRequestRateProgress,
  resolveMetricsViewerMetrics,
} from './metricsFlow';

describe('metricsFlow helpers', () => {
  it('normalizes metrics payloads with fallback chart data', () => {
    expect(resolveMetricsViewerMetrics({
      cpu_usage: 41,
      transaction_volume: [{ name: 'now', issuance: 1, verification: 2 }],
    })).toEqual({
      ...METRICS_VIEWER_DEFAULT_METRICS,
      cpu_usage: 41,
      transaction_volume: [{ name: 'now', issuance: 1, verification: 2 }],
    });

    expect(resolveMetricsViewerMetrics(null)).toEqual(METRICS_VIEWER_DEFAULT_METRICS);
    expect(METRICS_VIEWER_CHART_FALLBACK).toHaveLength(7);
  });

  it('calculates request-rate progress for the progress bar', () => {
    expect(getMetricsViewerRequestRateProgress(30)).toBe(30);
    expect(getMetricsViewerRequestRateProgress(250)).toBe(100);
    expect(getMetricsViewerRequestRateProgress(0)).toBe(0);
  });
});
