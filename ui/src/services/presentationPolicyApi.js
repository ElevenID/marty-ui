/**
 * Presentation Policy API Service
 * 
 * Provides CRUD operations for Presentation Policies and related resources
 */

import { get, post, patch, del } from './api';

/**
 * Create a new presentation policy
 */
export async function createPresentationPolicy(data) {
  return post('/api/v1/identity/presentation-policies', data);
}

/**
 * List all presentation policies
 * @param {Object} params - Query parameters (trust_profile_id, etc.)
 */
export async function listPresentationPolicies(params = {}) {
  return get('/api/v1/identity/presentation-policies', { params });
}

/**
 * Get a specific presentation policy by ID
 */
export async function getPresentationPolicy(id) {
  return get(`/api/v1/identity/presentation-policies/${id}`);
}

/**
 * Update a presentation policy
 */
export async function updatePresentationPolicy(id, data) {
  return patch(`/api/v1/identity/presentation-policies/${id}`, data);
}

/**
 * Delete a presentation policy
 */
export async function deletePresentationPolicy(id) {
  return del(`/api/v1/identity/presentation-policies/${id}`);
}

/**
 * List credential templates (for claim name autocomplete)
 */
export async function listCredentialTemplates(params = {}) {
  return get('/api/v1/identity/credential-templates', { params });
}

/**
 * Get a specific credential template by ID
 */
export async function getCredentialTemplate(id) {
  return get(`/api/v1/identity/credential-templates/${id}`);
}

/**
 * List organization trust profiles
 */
export async function listTrustProfiles(params = {}) {
  return get('/api/v1/identity/trust-profiles', { params });
}

/**
 * Get a specific trust profile by ID
 */
export async function getTrustProfile(id) {
  return get(`/api/v1/identity/trust-profiles/${id}`);
}
