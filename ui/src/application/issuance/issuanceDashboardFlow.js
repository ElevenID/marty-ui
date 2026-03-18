/**
 * Pure helpers for issuance dashboard metrics.
 */

export function parseIssuanceMetrics(data) {
  return {
    activeOffers: data.active_offers || 0,
    totalScans: data.total_scans || 0,
    successRate: data.success_rate || 0,
    totalOffers: data.total_offers || 0,
  };
}
