/**
 * Vendor API service layer.
 *
 * Centralises all vendor-area fetch() calls behind the project's
 * standard get/post/put/del helpers so components never talk to
 * `fetch` directly.
 */

import { get, post, put, del } from '../../services/api';

const API_URL = import.meta.env.VITE_API_URL || '';

// ── Credential Configuration ──────────────────────────────────────

export async function fetchCredentialConfigs({ organizationId }) {
  return get(`${API_URL}/api/organizations/${organizationId}/credential-types`);
}

export async function fetchCredentialTypeDefaults({ credentialType }) {
  return get(`${API_URL}/api/organizations/credential-types/defaults/${credentialType}`);
}

export async function saveCredentialConfig({ organizationId, id, body }) {
  return id
    ? put(`${API_URL}/api/organizations/${organizationId}/credential-types/${id}`, body)
    : post(`${API_URL}/api/organizations/${organizationId}/credential-types`, body);
}

export async function deleteCredentialConfig({ organizationId, id }) {
  return del(`${API_URL}/api/organizations/${organizationId}/credential-types/${id}`);
}

export async function toggleCredentialConfigActive({ organizationId, id, isActive }) {
  return put(`${API_URL}/api/organizations/${organizationId}/credential-types/${id}`, { is_active: isActive });
}

// ── Credential Type Actions (publish/preview/versions/unpublish) ──

export async function publishCredentialType({ orgId, typeId, visibility, changeDescription }) {
  return post(
    `${API_URL}/api/organizations/${orgId}/credential-types/${typeId}/publish?visibility=${encodeURIComponent(visibility)}`,
    { change_description: changeDescription },
  );
}

export async function previewCredentialType({ orgId, typeId, testData }) {
  return post(`${API_URL}/api/organizations/${orgId}/credential-types/${typeId}/preview`, testData);
}

export async function fetchCredentialTypeVersions({ orgId, typeId }) {
  return get(`${API_URL}/api/organizations/${orgId}/credential-types/${typeId}/versions`);
}

export async function unpublishCredentialType({ orgId, typeId }) {
  return post(`${API_URL}/api/organizations/${orgId}/credential-types/${typeId}/unpublish`);
}

// ── Offers ────────────────────────────────────────────────────────

export async function fetchOffers({ organizationId, page, pageSize, statusFilter, activeFilter }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    page: String(page),
    page_size: String(pageSize),
  });
  if (statusFilter) params.append('status', statusFilter);
  if (activeFilter !== '' && activeFilter !== undefined) params.append('is_active', activeFilter);
  return get(`${API_URL}/api/issuance/offers?${params.toString()}`);
}

export async function regenerateOffer({ offerId }) {
  return post(`${API_URL}/api/issuance/offers/${offerId}/regenerate`, { force: false });
}

// ── Offer Analytics ───────────────────────────────────────────────

export async function fetchAnalyticsSummary({ organizationId, days = 30 }) {
  const params = new URLSearchParams({ organization_id: organizationId, days: String(days) });
  return get(`${API_URL}/api/issuance/analytics/summary?${params.toString()}`);
}

export async function fetchAnalyticsScans({ organizationId, page, pageSize, accessTypeFilter, outcomeFilter, walletTypeFilter }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    page: String(page),
    page_size: String(pageSize),
  });
  if (accessTypeFilter) params.append('access_type', accessTypeFilter);
  if (outcomeFilter) params.append('outcome', outcomeFilter);
  if (walletTypeFilter) params.append('wallet_type', walletTypeFilter);
  return get(`${API_URL}/api/issuance/analytics/scans?${params.toString()}`);
}

// ── Revocation ────────────────────────────────────────────────────

export async function fetchIssuedCredentials({ organizationId, page, perPage, searchQuery }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
  });

  const data = await get(`${API_URL}/v1/issued-credentials?${params.toString()}`);
  const records = Array.isArray(data)
    ? data
    : (data?.credentials || data?.items || data?.issued_credentials || []);

  const normalized = records
    .map((record) => ({
      ...record,
      type: record.credential_display_name || record.credential_type || 'Credential',
      holder_email: record.holder_email || record.subject_email || record.subject_id || 'Unknown holder',
      issued_date: record.issued_date || record.issued_at,
      expiry_date: record.expiry_date || record.valid_until,
      application_id: record.application_id || null,
    }))
    .sort((left, right) => new Date(right.issued_date || 0).getTime() - new Date(left.issued_date || 0).getTime());

  const query = (searchQuery || '').trim().toLowerCase();
  const filtered = query
    ? normalized.filter((record) => [
      record.id,
      record.credential_id,
      record.credential_type,
      record.type,
      record.holder_email,
      record.subject_id,
      record.application_id,
      record.issuer_did,
    ].some((value) => String(value || '').toLowerCase().includes(query)))
    : normalized;

  const safePage = Math.max(page || 1, 1);
  const safePerPage = Math.max(perPage || filtered.length || 1, 1);
  const start = (safePage - 1) * safePerPage;
  const end = start + safePerPage;

  return {
    credentials: filtered.slice(start, end),
    total: filtered.length,
    page: safePage,
    perPage: safePerPage,
  };
}

export async function revokeCredential({ credentialId, reason, comments }) {
  return post(`${API_URL}/v1/issued-credentials/${credentialId}/revoke`, { reason, comments });
}

export async function batchRevokeCredentials({ file, reason }) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('reason', reason);
  // Use raw fetch for FormData (no JSON content-type)
  const response = await fetch(`${API_URL}/v1/credentials/issued/batch-revoke`, {
    method: 'POST',
    credentials: 'include',
    body: formData,
  });
  if (!response.ok) {
    throw new Error(`Failed to batch revoke: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchRevocationHistory({ organizationId, limit, offset }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    limit: String(limit),
    offset: String(offset),
  });
  return get(`${API_URL}/v1/credentials/revocations?${params.toString()}`);
}

// ── mDoc Configuration ────────────────────────────────────────────

export async function fetchMDocConfig({ organizationId }) {
  return get(`${API_URL}/api/organizations/${organizationId}/mdoc-config`);
}

export async function saveMDocConfig({ organizationId, enabledTypes, typeConfigs }) {
  return put(`${API_URL}/api/organizations/${organizationId}/mdoc-config`, {
    enabled_types: enabledTypes,
    type_configs: typeConfigs,
  });
}

// ── Issuance Templates ───────────────────────────────────────────

export async function fetchIssuanceTemplates({ organizationId }) {
  return get(`${API_URL}/v1/issuance/templates?organization_id=${organizationId}`);
}

export async function fetchTrustProfiles({ organizationId }) {
  return get(`${API_URL}/v1/trust-profiles?organization_id=${organizationId}`);
}

export async function saveIssuanceTemplate({ templateData, organizationId }) {
  const method = templateData.id ? 'PUT' : 'POST';
  const url = templateData.id
    ? `${API_URL}/v1/issuance/templates/${templateData.id}`
    : `${API_URL}/v1/issuance/templates`;
  const body = { ...templateData, organization_id: organizationId };
  return method === 'PUT' ? put(url, body) : post(url, body);
}

export async function deleteIssuanceTemplate({ templateId }) {
  return del(`${API_URL}/v1/issuance/templates/${templateId}`);
}

// ── Audit Logs ────────────────────────────────────────────────────

export async function fetchAuditEvents({ organizationId, page, perPage, timeRange, categoryFilter, severityFilter, searchQuery }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    page: String(page),
    per_page: String(perPage),
    time_range: timeRange,
  });
  if (categoryFilter && categoryFilter !== 'all') params.append('category', categoryFilter);
  if (severityFilter && severityFilter !== 'all') params.append('severity', severityFilter);
  if (searchQuery) params.append('search', searchQuery);
  return get(`${API_URL}/v1/organizations/audit/events?${params.toString()}`);
}

export async function exportAuditEvents({ organizationId, format, timeRange, categoryFilter, severityFilter }) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    format,
    time_range: timeRange,
  });
  if (categoryFilter && categoryFilter !== 'all') params.append('category', categoryFilter);
  if (severityFilter && severityFilter !== 'all') params.append('severity', severityFilter);
  // Returns a Blob for file download
  const response = await fetch(`${API_URL}/v1/organizations/audit/events/export?${params.toString()}`, {
    method: 'GET',
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error(`Failed to export: ${response.statusText}`);
  }
  return response.blob();
}

// ── Preview ───────────────────────────────────────────────────────

export async function fetchPreviewFlow({ flowId }) {
  return get(`${API_URL}/api/v1/identity/flows/${flowId}?preview=true`);
}

export async function fetchPreviewCredentialTemplate({ templateId }) {
  return get(`${API_URL}/api/credential-templates/${templateId}?preview=true`);
}

// ── Wallet Pairing ────────────────────────────────────────────────

export async function generateWalletPairingQR() {
  return post(`${API_URL}/wallet/pairing/generate`);
}

export async function fetchWalletPairingStatus({ pairingToken }) {
  return get(`${API_URL}/wallet/pairing/${pairingToken}/status`);
}
