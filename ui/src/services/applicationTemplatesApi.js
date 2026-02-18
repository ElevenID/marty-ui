/**
 * Application Templates API Service
 *
 * CRUD operations for credential application templates, including
 * the required_checks configuration that defines pluggable vetting checks.
 */

const API_BASE = '/v1/application-templates';

async function _handleResponse(response) {
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      detail = body.detail || body.message || detail;
    } catch {/* ignore */}
    throw new Error(detail);
  }
  if (response.status === 204) return null;
  return response.json();
}

// ── Listing ──────────────────────────────────────────────────────────────────

export async function listApplicationTemplates(organizationId) {
  const response = await fetch(`${API_BASE}?organization_id=${encodeURIComponent(organizationId)}`);
  return _handleResponse(response);
}

// ── Single template ───────────────────────────────────────────────────────────

export async function getApplicationTemplate(templateId) {
  const response = await fetch(`${API_BASE}/${templateId}`);
  return _handleResponse(response);
}

export async function createApplicationTemplate(data) {
  const response = await fetch(API_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return _handleResponse(response);
}

/**
 * Full update (PUT) for an existing application template.
 * Use this when saving changes including required_checks.
 */
export async function updateApplicationTemplate(templateId, data) {
  const response = await fetch(`${API_BASE}/${templateId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return _handleResponse(response);
}

export async function deleteApplicationTemplate(templateId) {
  const response = await fetch(`${API_BASE}/${templateId}`, { method: 'DELETE' });
  return _handleResponse(response);
}

// ── Required checks helpers ───────────────────────────────────────────────────

/**
 * Update only the required_checks of a template, preserving everything else.
 */
export async function updateTemplateRequiredChecks(templateId, requiredChecks) {
  const template = await getApplicationTemplate(templateId);
  return updateApplicationTemplate(templateId, { ...template, required_checks: requiredChecks });
}
