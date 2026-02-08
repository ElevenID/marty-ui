/**
 * Presentation Policy API Service
 * 
 * Provides CRUD operations for Presentation Policies, Credential Templates, and Trust Profiles.
 * Each resource type is now managed by its own dedicated service.
 */

import { get, post, patch, del } from './api';

// Each resource type has its own service
const PRESENTATION_POLICY_BASE = '/v1/presentation-policies';
const CREDENTIAL_TEMPLATE_BASE = '/v1/credential-templates';
const TRUST_PROFILE_BASE = '/v1/trust-profiles';

/**
 * Create a new presentation policy
 */
export async function createPresentationPolicy(data) {
  return post(PRESENTATION_POLICY_BASE, data);
}

/**
 * List all presentation policies
 * @param {Object} params - Query parameters (organization_id, etc.)
 */
export async function listPresentationPolicies(params = {}) {
  return get(PRESENTATION_POLICY_BASE, { params });
}

/**
 * Get a specific presentation policy by ID
 */
export async function getPresentationPolicy(id) {
  return get(`${PRESENTATION_POLICY_BASE}/${id}`);
}

/**
 * Update a presentation policy
 */
export async function updatePresentationPolicy(id, data) {
  return patch(`${PRESENTATION_POLICY_BASE}/${id}`, data);
}

/**
 * Delete a presentation policy
 */
export async function deletePresentationPolicy(id) {
  return del(`${PRESENTATION_POLICY_BASE}/${id}`);
}

/**
 * Create a new credential template
 */
export async function createCredentialTemplate(data) {
  return post(CREDENTIAL_TEMPLATE_BASE, data);
}

/**
 * List credential templates (for claim name autocomplete)
 */
export async function listCredentialTemplates(params = {}) {
  return get(CREDENTIAL_TEMPLATE_BASE, { params });
}

/**
 * Get a specific credential template by ID
 */
export async function getCredentialTemplate(id) {
  return get(`${CREDENTIAL_TEMPLATE_BASE}/${id}`);
}

/**
 * Update a credential template
 */
export async function updateCredentialTemplate(id, data) {
  return patch(`${CREDENTIAL_TEMPLATE_BASE}/${id}`, data);
}

/**
 * Delete a credential template
 */
export async function deleteCredentialTemplate(id) {
  return del(`${CREDENTIAL_TEMPLATE_BASE}/${id}`);
}

/**
 * Create a new trust profile
 */
export async function createTrustProfile(data) {
  return post(TRUST_PROFILE_BASE, data);
}

/**
 * List organization trust profiles
 */
export async function listTrustProfiles(params = {}) {
  return get(TRUST_PROFILE_BASE, { params });
}

/**
 * Get a specific trust profile by ID
 */
export async function getTrustProfile(id) {
  return get(`${TRUST_PROFILE_BASE}/${id}`);
}

/**
 * Update a trust profile
 */
export async function updateTrustProfile(id, data) {
  return patch(`${TRUST_PROFILE_BASE}/${id}`, data);
}

/**
 * Delete a trust profile
 */
export async function deleteTrustProfile(id) {
  return del(`${TRUST_PROFILE_BASE}/${id}`);
}
