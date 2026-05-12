/**
 * Credentials API Service
 * 
 * Handles credential issuance, verification, and revocation operations.
 * Integrates with digital identity backend for credential lifecycle management.
 */

import { apiClient, handleApiError } from './api';

const BASE_PATH = '/v1/credentials';

/**
 * Issue a credential
 * @param {Object} request - Credential issuance request
 * @param {string} request.credential_template_id - Template ID
 * @param {string} request.flow_execution_id - Optional flow execution ID
 * @param {Object} request.subject_claims - Claims for the credential subject
 * @param {string} request.holder_identifier - Holder DID or identifier
 * @param {Object} request.application_data - Optional application evidence
 * @returns {Promise<Object>} Issued credential response with credential and metadata
 */
export const issueCredential = async (request) => {
  try {
    const response = await apiClient.post(`${BASE_PATH}/issue`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Verify a credential
 * @param {Object} request - Verification request
 * @param {Object|string} request.credential - Credential to verify
 * @param {string} request.presentation_policy_id - Optional policy ID
 * @param {string} request.trust_profile_id - Optional trust profile ID
 * @returns {Promise<Object>} Verification result
 */
export const verifyCredential = async (request) => {
  try {
    const response = await apiClient.post(`${BASE_PATH}/verify`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get credential metadata by ID
 * @param {string} credentialId - Credential ID
 * @returns {Promise<Object>} Credential metadata (no actual credential data)
 */
export const getCredentialMetadata = async (credentialId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${credentialId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Revoke a single credential
 * @param {string} credentialId - Credential ID to revoke
 * @param {Object} options - Revocation options
 * @param {string} options.revocation_reason - Optional reason
 * @param {string} options.revocation_strategy - 'scheduled' (default) or 'immediate' (privacy warning)
 * @returns {Promise<Object>} Revocation result
 */
export const revokeCredential = async (credentialId, options = {}) => {
  try {
    const request = {
      revocation_reason: options.revocation_reason,
      revocation_strategy: options.revocation_strategy || 'scheduled',
    };
    const response = await apiClient.patch(`${BASE_PATH}/${credentialId}/revoke`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Batch revoke multiple credentials
 * @param {Array<string>} credentialIds - Array of credential IDs
 * @param {Object} options - Revocation options
 * @param {string} options.revocation_reason - Optional reason
 * @param {string} options.revocation_strategy - 'scheduled' (default) or 'immediate'
 * @returns {Promise<Object>} Batch revocation result with batch_id
 */
export const batchRevokeCredentials = async (credentialIds, options = {}) => {
  try {
    const request = {
      credential_ids: credentialIds,
      revocation_reason: options.revocation_reason,
      revocation_strategy: options.revocation_strategy || 'scheduled',
    };
    const response = await apiClient.post(`${BASE_PATH}/revoke/batch`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * List credentials with optional filters
 * @param {Object} filters - Query filters
 * @param {string} filters.flow_id - Optional flow ID filter
 * @param {string} filters.credential_template_id - Optional template ID filter
 * @param {string} filters.status - Optional status filter
 * @param {number} filters.limit - Page size (default 50)
 * @param {number} filters.offset - Offset for pagination (default 0)
 * @returns {Promise<Array>} List of credential metadata
 */
export const listCredentials = async (filters = {}) => {
  try {
    const params = new URLSearchParams();
    if (filters.organization_id) params.append('organization_id', filters.organization_id);
    if (filters.flow_id) params.append('flow_id', filters.flow_id);
    if (filters.credential_template_id) params.append('credential_template_id', filters.credential_template_id);
    if (filters.status) params.append('status', filters.status);
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);
    
    const response = await apiClient.get(`${BASE_PATH}?${params.toString()}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * List revocation batches
 * @param {Object} filters - Query filters
 * @param {string} filters.status - Optional status filter (pending, processing, completed, failed)
 * @returns {Promise<Array>} List of revocation batch statuses
 */
export const listRevocationBatches = async (filters = {}) => {
  try {
    const params = new URLSearchParams();
    if (filters.organization_id) params.append('organization_id', filters.organization_id);
    if (filters.status) params.append('status', filters.status);
    
    const response = await apiClient.get(`${BASE_PATH}/revocation-batches?${params.toString()}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Create a credential offer for OID4VCI issuance
 * @param {Object} request - Credential offer request
 * @param {string} request.applicantId - Applicant/recipient ID
 * @param {string} request.templateId - Credential template ID
 * @param {Object} request.credentialData - Claim values for the credential
 * @param {number} request.expiryMinutes - QR code expiry time in minutes (default 15)
 * @returns {Promise<Object>} Generated credential offer with QR code
 */
export const createCredentialOffer = async (request) => {
  try {
    const payload = {
      credential_config_id: request.templateId,
      applicant_id: request.applicantId,
      credential_data: request.credentialData,
      credential_format: 'dc+sd-jwt',
      deferred: false,
    };
    
    const response = await apiClient.post('/v1/issuance/offers', payload);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get credential offer by ID
 * @param {string} offerId - Offer ID or session ID
 * @returns {Promise<Object>} Credential offer details
 */
export const getCredentialOffer = async (offerId) => {
  try {
    const response = await apiClient.get(`/v1/issuance/offers/${offerId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get QR code image for a credential offer
 * @param {string} offerId - Offer ID
 * @param {string} format - Image format ('png' or 'svg')
 * @returns {Promise<Blob>} QR code image blob
 */
export const getOfferQRCode = async (offerId, format = 'png') => {
  try {
    const response = await apiClient.get(
      `/v1/issuance/offers/${offerId}/qr?format=${format}`,
      { responseType: 'blob' }
    );
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get issuance session status
 * @param {string} transactionId - Transaction ID
 * @returns {Promise<Object>} Issuance session status
 */
export const getIssuanceSessionStatus = async (transactionId) => {
  try {
    const response = await apiClient.get(`/v1/issuance/transactions/${transactionId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Generate (or refresh) the issuance offer for an application.
 * Uses the applicant issue endpoint, which now delegates issuance strictly
 * through flow orchestration (no direct issuance fallback).
 *
 * @param {string} applicationId
 * @returns {Promise<{offer_url: string, expires_at: string|null, status: string}>}
 */
export const generateIssuanceOffer = async (applicationId) => {
  try {
    const response = await apiClient.post(`/v1/applicants/applications/${applicationId}/issue`);
    const data = response.data;
    // Normalise to the shape OID4VCIInviteDisplay / IssuingSection expect
    return {
      offer_url: data.credential_offer_uri || data.offer_url || null,
      expires_at: data.offer_expires_at || data.expires_at || null,
      status: data.status || (data.credential_offer_uri || data.offer_url ? 'active' : 'pending'),
      // Pass through in case callers want raw fields too
      ...data,
    };
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Retrieve the current issuance offer for an application (applicant-facing).
 *
 * @param {string} applicationId
 * @returns {Promise<Object>} IssuanceOfferResponse
 */
export const getIssuanceOffer = async (applicationId) => {
  try {
    const response = await apiClient.get(`/v1/applications/${applicationId}/issuance-offer`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export default {
  issueCredential,
  verifyCredential,
  getCredentialMetadata,
  revokeCredential,
  batchRevokeCredentials,
  listCredentials,
  listRevocationBatches,
  createCredentialOffer,
  getCredentialOffer,
  getOfferQRCode,
  getIssuanceSessionStatus,
  generateIssuanceOffer,
  getIssuanceOffer,
};
