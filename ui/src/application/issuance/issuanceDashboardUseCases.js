/**
 * Use cases for issuance dashboard metrics.
 */

import { get, getErrorMessage } from '../../services/api';
import { parseIssuanceMetrics } from './issuanceDashboardFlow';

const API_URL = import.meta.env.VITE_API_URL || '';

async function defaultFetchAnalyticsSummary({ organizationId, days = 1 }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    days: String(days),
  });
  return get(`${API_URL}/api/issuance/analytics/summary?${params.toString()}`);
}

export async function loadIssuanceMetrics({
  organizationId,
  days = 1,
  fetchSummary = defaultFetchAnalyticsSummary,
} = {}) {
  try {
    const data = await fetchSummary({ organizationId, days });
    return { metrics: parseIssuanceMetrics(data), error: null };
  } catch (error) {
    return {
      metrics: null,
      error: getErrorMessage(error) || 'Failed to load issuance metrics',
    };
  }
}
