/**
 * Application Templates API Service
 *
 * CRUD operations for credential application templates, including
 * the required_checks configuration that defines pluggable vetting checks.
 */

import { get, post, put, del } from './api';

const API_BASE = '/v1/application-templates';

// ── Listing ──────────────────────────────────────────────────────────────────

export async function listApplicationTemplates(organizationId) {
  return get(`${API_BASE}?organization_id=${encodeURIComponent(organizationId)}`);
}

// ── Single template ───────────────────────────────────────────────────────────

/** Internal helper — used by updateTemplateRequiredChecks. */
async function getApplicationTemplate(templateId) {
  return get(`${API_BASE}/${templateId}`);
}

export async function createApplicationTemplate(data) {
  return post(API_BASE, data);
}

/**
 * Full update (PUT) for an existing application template.
 * Use this when saving changes including required_checks.
 */
export async function updateApplicationTemplate(templateId, data) {
  return put(`${API_BASE}/${templateId}`, data);
}

export async function deleteApplicationTemplate(templateId) {
  return del(`${API_BASE}/${templateId}`);
}

// ── Required checks helpers ───────────────────────────────────────────────────

/**
 * Update only the required_checks of a template, preserving everything else.
 */
export async function updateTemplateRequiredChecks(templateId, requiredChecks) {
  const template = await getApplicationTemplate(templateId);
  return updateApplicationTemplate(templateId, { ...template, required_checks: requiredChecks });
}
