/**
 * Flows API Service
 * 
 * Manages digital identity flows (issuance + presentation orchestration).
 * Flows tie together Trust Profiles, Credential Templates, Presentation Policies,
 * and Deployment Profiles for end-to-end credential lifecycle management.
 */

import { apiClient, handleApiError } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, withQuery } from './queryUtils';

const FLOW_DEFINITIONS_PATH = '/v1/flows/definitions';
const FLOW_INSTANCES_PATH = '/v1/flows/instances';
const FLOW_CAPABILITIES_PATH = '/v1/flows/capabilities';

function createUnsupportedFlowActionError(message) {
  const error = new Error(message);
  error.status = 501;
  return error;
}

function resolveOrganizationId(organizationId) {
  return organizationId || null;
}

function requireOrganizationId(organizationId) {
  const resolved = resolveOrganizationId(organizationId);
  const normalized = String(resolved ?? '').trim();
  if (
    normalized === ''
    || normalized.toLowerCase() === 'null'
    || normalized.toLowerCase() === 'undefined'
  ) {
    const error = new Error('An active organization is required before loading flows.');
    error.code = 'ORG_REQUIRED';
    error.status = 400;
    throw error;
  }
  return normalized;
}

/**
 * Flow state constants
 */
export const FLOW_STATES = {
  DRAFT: 'DRAFT',
  ACTIVE: 'ACTIVE',
  PAUSED: 'PAUSED',
  ARCHIVED: 'ARCHIVED',
};

/**
 * Flow approval strategies (MIP §9)
 */
export const APPROVAL_STRATEGIES = {
  AUTO: 'AUTO',
  MANUAL: 'MANUAL',
  RULES_BASED: 'RULES_BASED',
  EXTERNAL: 'EXTERNAL',
};

function requireDirectArray(value, resourceName) {
  if (!Array.isArray(value)) {
    const error = new Error(`${resourceName} service returned a malformed list response.`);
    error.code = 'MALFORMED_RESPONSE';
    throw error;
  }
  return value;
}

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
 * @param {string} flowData.approval_strategy - AUTO, MANUAL, RULES_BASED, EXTERNAL
 * @param {Object} flowData.steps - Flow step configuration
 * @returns {Promise<Object>} Created flow
 */
export const createFlow = async (flowData) => {
  try {
    const organizationId = requireOrganizationId(flowData?.organization_id);
    const payload = {
      ...flowData,
      organization_id: organizationId,
    };
    return await postWithIdempotency(FLOW_DEFINITIONS_PATH, payload);
  } catch (error) {
    if (error?.operationStatusUnknown) {
      throw error;
    }
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
    const queryString = buildDefinedQueryString({
      organization_id: requireOrganizationId(filters.organization_id),
      flow_type: filters.flow_type,
      limit: filters.limit,
      offset: filters.offset,
    });

    const response = await apiClient.get(withQuery(FLOW_DEFINITIONS_PATH, queryString));
    return requireDirectArray(response.data, 'Flow Definition');
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
    const response = await apiClient.get(`${FLOW_DEFINITIONS_PATH}/${flowId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const getFlowCapabilities = async () => {
  try {
    const response = await apiClient.get(FLOW_CAPABILITIES_PATH);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const validateFlow = async (flowId) => {
  try {
    const response = await apiClient.post(`${FLOW_DEFINITIONS_PATH}/${flowId}/validate`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export const testFlow = async (flowId) => {
  try {
    const response = await apiClient.post(`${FLOW_DEFINITIONS_PATH}/${flowId}/test`);
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
    const response = await apiClient.put(`${FLOW_DEFINITIONS_PATH}/${flowId}`, updates);
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
    await apiClient.delete(`${FLOW_DEFINITIONS_PATH}/${flowId}`);
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
    const response = await apiClient.post(FLOW_INSTANCES_PATH, {
      flow_definition_id: flowId,
      initial_context: context,
    });
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
  return listFlowInstances({ ...filters, flow_definition_id: flowId });
};

/** List runtime instances across an organization, optionally filtered by flow. */
export const listFlowInstances = async (filters = {}) => {
  try {
    const queryString = buildDefinedQueryString({
      organization_id: requireOrganizationId(filters.organization_id),
      flow_definition_id: filters.flow_definition_id,
      status: filters.status,
      limit: filters.limit,
      offset: filters.offset,
    });

    const response = await apiClient.get(withQuery(FLOW_INSTANCES_PATH, queryString));
    return requireDirectArray(response.data, 'Flow Instance');
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
  return getFlowInstance(executionId);
};

/** Get one runtime instance by its stable instance identifier. */
export const getFlowInstance = async (instanceId) => {
  try {
    const response = await apiClient.get(`${FLOW_INSTANCES_PATH}/${instanceId}`);
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
    const response = await apiClient.post(`${FLOW_INSTANCES_PATH}/${executionId}/advance`, {
      step_result: 'success',
      data: {
        flow_definition_id: flowId,
        approver_id: approvalData.approver_id,
        approval_notes: approvalData.notes,
      },
    });
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
    const response = await apiClient.post(`${FLOW_INSTANCES_PATH}/${executionId}/advance`, {
      step_result: 'failure',
      data: {
        flow_definition_id: flowId,
        rejection_reason: rejectionData?.reason,
        rejection_notes: rejectionData?.notes,
      },
    });
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
    const response = await apiClient.post(`${FLOW_INSTANCES_PATH}/${executionId}/cancel`, { reason });
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
    const response = await apiClient.post(`${FLOW_DEFINITIONS_PATH}/${flowId}/activate`, publishData);
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
  void flowId;
  void disableData;
  throw createUnsupportedFlowActionError('Disabling flow definitions is not supported by this environment yet.');
};

/**
 * Archive a flow - mark as ARCHIVED (terminal, no new instances)
 * @param {string} flowId
 * @param {Object} archiveData
 * @param {string} archiveData.reason
 * @returns {Promise<Object>} Archived flow
 */
export const archiveFlow = async (flowId, archiveData = {}) => {
  void flowId;
  void archiveData;
  throw createUnsupportedFlowActionError('Archiving flow definitions is not supported by this environment yet.');
};

/**
 * Get public application URL for a published flow
 * @param {string} flowId - Flow ID
 * @returns {Promise<Object>} Public URL and QR code data
 */
export const getFlowPublicUrl = async (flowId) => {
  void flowId;
  throw createUnsupportedFlowActionError('Public flow URLs are derived client-side in this environment.');
};

export default {
  createFlow,
  getFlowCapabilities,
  validateFlow,
  testFlow,
  listFlows,
  getFlow,
  updateFlow,
  deleteFlow,
  startFlowExecution,
  listFlowExecutions,
  listFlowInstances,
  getFlowExecution,
  getFlowInstance,
  approveFlowExecution,
  rejectFlowExecution,
  cancelFlowExecution,
  publishFlow,
  disableFlow,
  archiveFlow,
  getFlowPublicUrl,
  FLOW_STATES,
  APPROVAL_STRATEGIES,
};
