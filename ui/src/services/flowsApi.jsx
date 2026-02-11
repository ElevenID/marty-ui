/**
 * Flows API Service
 * 
 * Manages digital identity flows (issuance + presentation orchestration).
 * Flows tie together Trust Profiles, Credential Templates, Presentation Policies,
 * and Deployment Profiles for end-to-end credential lifecycle management.
 */

import { apiClient, handleApiError } from './api';

const BASE_PATH = '/v1/identity/flows';

/**
 * Flow state constants
 */
export const FLOW_STATES = {
  DRAFT: 'draft',
  PUBLISHED: 'published',
  DISABLED: 'disabled',
};

/**
 * Flow approval strategies
 */
export const APPROVAL_STRATEGIES = {
  AUTO: 'AUTO',
  MANUAL: 'MANUAL',
  AUTOMATED_RULES: 'AUTOMATED_RULES',
  MULTI_PARTY: 'MULTI_PARTY',
};

/**
 * Create a new flow
 * @param {Object} flowData - Flow configuration
 * @param {string} flowData.name - Flow name
 * @param {string} flowData.flow_type - Flow type (oid4vci_pre_authorized, oid4vp, etc.)
 * @param {string} flowData.description - Optional description
 * @param {string} flowData.trust_profile_id - Trust profile ID
 * @param {string} flowData.credential_template_id - Optional credential template for issuance flows
 * @param {string} flowData.presentation_policy_id - Optional presentation policy for verification flows
 * @param {string} flowData.deployment_profile_id - Optional deployment profile
 * @param {string} flowData.approval_strategy - AUTO, MANUAL, AUTOMATED_RULES, MULTI_PARTY
 * @param {Object} flowData.steps - Flow step configuration
 * @returns {Promise<Object>} Created flow
 */
export const createFlow = async (flowData) => {
  try {
    const response = await apiClient.post(BASE_PATH, flowData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * List flows with optional filters
 * @param {Object} filters - Query filters
 * @param {string} filters.flow_type - Optional flow type filter
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of flows
 */
export const listFlows = async (filters = {}) => {
  try {
    const params = new URLSearchParams();
    if (filters.flow_type) params.append('flow_type', filters.flow_type);
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);
    
    const response = await apiClient.get(`${BASE_PATH}?${params.toString()}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get flow by ID
 * @param {string} flowId - Flow ID
 * @returns {Promise<Object>} Flow details
 */
export const getFlow = async (flowId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${flowId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Update flow
 * @param {string} flowId - Flow ID
 * @param {Object} updates - Flow updates
 * @returns {Promise<Object>} Updated flow
 */
export const updateFlow = async (flowId, updates) => {
  try {
    const response = await apiClient.patch(`${BASE_PATH}/${flowId}`, updates);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Delete flow
 * @param {string} flowId - Flow ID
 * @returns {Promise<void>}
 */
export const deleteFlow = async (flowId) => {
  try {
    await apiClient.delete(`${BASE_PATH}/${flowId}`);
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Start a flow execution
 * @param {string} flowId - Flow ID
 * @param {Object} context - Execution context data
 * @returns {Promise<Object>} Flow execution
 */
export const startFlowExecution = async (flowId, context = {}) => {
  try {
    const response = await apiClient.post(`${BASE_PATH}/${flowId}/executions`, { context });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * List flow executions
 * @param {string} flowId - Flow ID
 * @param {Object} filters - Query filters
 * @param {string} filters.status - Optional status filter
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of executions
 */
export const listFlowExecutions = async (flowId, filters = {}) => {
  try {
    const params = new URLSearchParams();
    if (filters.status) params.append('status', filters.status);
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);
    
    const response = await apiClient.get(`${BASE_PATH}/${flowId}/executions?${params.toString()}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get flow execution by ID
 * @param {string} flowId - Flow ID
 * @param {string} executionId - Execution ID
 * @returns {Promise<Object>} Execution details
 */
export const getFlowExecution = async (flowId, executionId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${flowId}/executions/${executionId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Approve a flow execution (manual approval)
 * @param {string} flowId - Flow ID
 * @param {string} executionId - Execution ID
 * @param {Object} approvalData - Approval data
 * @param {string} approvalData.approver_id - Approver identifier
 * @param {string} approvalData.notes - Optional approval notes
 * @returns {Promise<Object>} Updated execution
 */
export const approveFlowExecution = async (flowId, executionId, approvalData = {}) => {
  try {
    const response = await apiClient.post(
      `${BASE_PATH}/${flowId}/executions/${executionId}/approve`,
      approvalData
    );
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Reject a flow execution (manual approval)
 * @param {string} flowId - Flow ID
 * @param {string} executionId - Execution ID
 * @param {Object} rejectionData - Rejection data
 * @param {string} rejectionData.reason - Rejection reason
 * @param {string} rejectionData.notes - Optional rejection notes
 * @returns {Promise<Object>} Updated execution
 */
export const rejectFlowExecution = async (flowId, executionId, rejectionData) => {
  try {
    const response = await apiClient.post(
      `${BASE_PATH}/${flowId}/executions/${executionId}/reject`,
      rejectionData
    );
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Cancel a flow execution
 * @param {string} flowId - Flow ID
 * @param {string} executionId - Execution ID
 * @param {string} reason - Optional cancellation reason
 * @returns {Promise<Object>} Updated execution
 */
export const cancelFlowExecution = async (flowId, executionId, reason) => {
  try {
    const response = await apiClient.post(
      `${BASE_PATH}/${flowId}/executions/${executionId}/cancel`,
      { reason }
    );
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Publish a flow - makes it available to applicants
 * @param {string} flowId - Flow ID
 * @param {Object} publishData - Publish configuration
 * @param {string} publishData.change_description - Optional description of changes
 * @returns {Promise<Object>} Published flow with public URL
 */
export const publishFlow = async (flowId, publishData = {}) => {
  try {
    const response = await apiClient.post(
      `${BASE_PATH}/${flowId}/publish`,
      publishData
    );
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Disable a flow - prevents new applications
 * @param {string} flowId - Flow ID
 * @param {Object} disableData - Disable configuration
 * @param {string} disableData.reason - Reason for disabling
 * @returns {Promise<Object>} Disabled flow
 */
export const disableFlow = async (flowId, disableData = {}) => {
  try {
    const response = await apiClient.post(
      `${BASE_PATH}/${flowId}/disable`,
      disableData
    );
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get public application URL for a published flow
 * @param {string} flowId - Flow ID
 * @returns {Promise<Object>} Public URL and QR code data
 */
export const getFlowPublicUrl = async (flowId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${flowId}/public-url`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export default {
  createFlow,
  listFlows,
  getFlow,
  updateFlow,
  deleteFlow,
  startFlowExecution,
  listFlowExecutions,
  getFlowExecution,
  approveFlowExecution,
  rejectFlowExecution,
  cancelFlowExecution,
  publishFlow,
  disableFlow,
  getFlowPublicUrl,
  FLOW_STATES,
  APPROVAL_STRATEGIES,
};
