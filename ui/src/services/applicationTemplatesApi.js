/**
 * Application Templates API Service
 *
 * CRUD operations for credential application templates, including
 * the required_checks configuration that defines pluggable vetting checks.
 */

import { get, patch, del, post } from './api';
import { postWithIdempotency } from './idempotency';

const API_BASE = '/v1/application-templates';

function requireOrganizationId(value) {
  const organizationId = String(value || '').trim();
  if (
    !organizationId
    || organizationId.toLowerCase() === 'null'
    || organizationId.toLowerCase() === 'undefined'
  ) {
    const error = new Error('organization_id is required');
    error.code = 'ORG_REQUIRED';
    error.status = 400;
    throw error;
  }
  return organizationId;
}

// ── Listing ──────────────────────────────────────────────────────────────────

export async function listApplicationTemplates(organizationId) {
  const orgId = requireOrganizationId(organizationId);
  return get(`${API_BASE}?organization_id=${encodeURIComponent(orgId)}`);
}

// ── Single template ───────────────────────────────────────────────────────────

/** Internal helper — used by updateTemplateRequiredChecks. */
export async function getApplicationTemplate(templateId) {
  return get(`${API_BASE}/${templateId}`);
}

export async function createApplicationTemplate(data) {
  const organizationId = requireOrganizationId(data?.organization_id || data?.organizationId);
  return postWithIdempotency(API_BASE, {
    ...data,
    organization_id: organizationId,
  });
}

/**
 * Patch mutable fields on a draft Application Template.
 */
export async function updateApplicationTemplate(templateId, data) {
  return patch(`${API_BASE}/${templateId}`, data);
}

export async function deleteApplicationTemplate(templateId) {
  return del(`${API_BASE}/${templateId}`);
}

export async function activateApplicationTemplate(templateId) {
  return post(`${API_BASE}/${templateId}/activate`, {});
}

export async function validateApplicationTemplate(templateId) {
  return post(`${API_BASE}/${templateId}/validate`, {});
}

export async function deprecateApplicationTemplate(templateId) {
  return post(`${API_BASE}/${templateId}/deprecate`, {});
}

// ── Required checks helpers ───────────────────────────────────────────────────

/**
 * Update only the required_checks of a template, preserving everything else.
 */
export async function updateTemplateRequiredChecks(templateId, requiredChecks) {
  return updateApplicationTemplate(templateId, { required_checks: requiredChecks });
}
