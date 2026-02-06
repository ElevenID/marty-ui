/**
 * ZK Verification API Service
 *
 * Handles Zero-Knowledge Proof (ZKP) challenge and verification operations.
 * Connects to the Flow and Presentation Policy services for credential verification.
 */

import { apiClient, handleApiError } from "./api";

// Flow service handles async verification flows (QR, wallet)
const FLOW_PATH = "/v1/flows";
// Presentation Policy handles stateless policy evaluation
const POLICY_PATH = "/v1/presentation-policies";

/**
 * Start a Verification Flow (async, for wallet/QR interactions)
 *
 * @param {Object} request - Flow request
 * @param {string} request.policy_id - Presentation Policy ID to evaluate against
 * @param {string} [request.purpose] - Human-readable verification purpose
 * @param {string} [request.verifier_id] - Optional verifier identifier
 * @returns {Promise<Object>} Flow instance with request_uri and qr_code_data
 */
export const startVerificationFlow = async (request) => {
  try {
    const response = await apiClient.post(`${FLOW_PATH}/verify`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get the verification request for a flow instance (wallet fetches this)
 *
 * @param {string} instanceId - Flow instance ID
 * @returns {Promise<Object>} OID4VP request object
 */
export const getVerificationRequest = async (instanceId) => {
  try {
    const response = await apiClient.get(`${FLOW_PATH}/instances/${instanceId}/request`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Submit a VP token to complete verification flow
 *
 * @param {string} instanceId - Flow instance ID
 * @param {Object} submission - Submission data
 * @param {string} submission.vp_token - Verifiable Presentation token
 * @returns {Promise<Object>} Verification result
 */
export const submitVerification = async (instanceId, submission) => {
  try {
    const response = await apiClient.post(`${FLOW_PATH}/instances/${instanceId}/submit`, submission);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Evaluate a Presentation Against a Saved Policy (stateless)
 *
 * @param {string} policyId - Presentation Policy ID
 * @param {Object} request - Evaluation request
 * @param {string} request.vp_token - Verifiable Presentation token
 * @returns {Promise<Object>} Evaluation result with decision and verified claims
 */
export const evaluatePresentation = async (policyId, request) => {
  try {
    const response = await apiClient.post(`${POLICY_PATH}/${policyId}/evaluate`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Evaluate a Presentation with Inline Policy (ad-hoc verification)
 *
 * @param {Object} request - Inline evaluation request
 * @param {Object} request.policy - Policy definition (inline)
 * @param {string} request.vp_token - Verifiable Presentation token
 * @returns {Promise<Object>} Evaluation result with decision and verified claims
 */
export const evaluateInline = async (request) => {
  try {
    const response = await apiClient.post(`${POLICY_PATH}/evaluate`, request);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

// Legacy aliases for backward compatibility during transition
export const createZkChallenge = startVerificationFlow;
export const verifyZkProof = submitVerification;

export default {
  startVerificationFlow,
  getVerificationRequest,
  submitVerification,
  evaluatePresentation,
  evaluateInline,
  // Legacy
  createZkChallenge,
  verifyZkProof,
};
