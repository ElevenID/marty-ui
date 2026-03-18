import { describe, expect, it, vi } from 'vitest';
import { parseIssuanceMetrics } from './issuanceDashboardFlow';
import { loadIssuanceMetrics } from './issuanceDashboardUseCases';

describe('issuanceDashboardFlow', () => {
  it('parses analytics response into metrics', () => {
    const metrics = parseIssuanceMetrics({
      active_offers: 5,
      total_scans: 120,
      success_rate: 0.95,
      total_offers: 200,
    });
    expect(metrics).toEqual({
      activeOffers: 5,
      totalScans: 120,
      successRate: 0.95,
      totalOffers: 200,
    });
  });

  it('defaults to zeros for missing fields', () => {
    expect(parseIssuanceMetrics({})).toEqual({
      activeOffers: 0,
      totalScans: 0,
      successRate: 0,
      totalOffers: 0,
    });
  });
});

describe('issuanceDashboardUseCases', () => {
  it('loads and parses metrics', async () => {
    const fetchSummary = vi.fn().mockResolvedValue({
      active_offers: 3,
      total_scans: 50,
      success_rate: 0.8,
      total_offers: 100,
    });

    const result = await loadIssuanceMetrics({
      organizationId: 'org-1',
      fetchSummary,
    });

    expect(result.error).toBeNull();
    expect(result.metrics.activeOffers).toBe(3);
    expect(fetchSummary).toHaveBeenCalledWith({ organizationId: 'org-1', days: 1 });
  });

  it('returns error on failure', async () => {
    const fetchSummary = vi.fn().mockRejectedValue(new Error('network'));
    const result = await loadIssuanceMetrics({ organizationId: 'org-1', fetchSummary });
    expect(result.metrics).toBeNull();
    expect(result.error).toBeTruthy();
  });
});
