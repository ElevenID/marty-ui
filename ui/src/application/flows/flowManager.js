/**
 * Pure helpers for the vendor flow management console.
 */

export const FLOW_MANAGER_MOCK_FLOWS = [
  {
    id: 'flow-1',
    name: 'EU Digital Identity – Employee Issuance',
    flow_type: 'issuance',
    status: 'PUBLISHED',
    approval_strategy: 'manual',
    credential_template_name: 'EU Digital Identity Credential',
    credential_template_id: 'ct-1',
  },
  {
    id: 'flow-2',
    name: 'Mobile Driver License Issuance',
    flow_type: 'issuance',
    status: 'DRAFT',
    approval_strategy: 'auto',
    credential_template_name: 'Mobile Driving License',
    credential_template_id: 'ct-2',
  },
];

export function getFlowManagerMockFlows() {
  return FLOW_MANAGER_MOCK_FLOWS.map((flow) => ({ ...flow }));
}

export function getFlowStatusPresentation(status, flowStates = {}) {
  const draftState = flowStates.DRAFT || 'DRAFT';
  const publishedState = flowStates.PUBLISHED || 'PUBLISHED';
  const normalizedStatus = status || draftState;
  const isDraft = normalizedStatus === draftState;
  const isPublished = normalizedStatus === publishedState;

  return {
    status: normalizedStatus,
    label: normalizedStatus.charAt(0).toUpperCase() + normalizedStatus.slice(1).toLowerCase(),
    color: isDraft ? 'default' : isPublished ? 'success' : 'error',
    icon: isDraft ? 'warning' : isPublished ? 'success' : 'error',
    isDraft,
    isPublished,
    isDisabled: !isDraft && !isPublished,
    hasApplicantEntry: isPublished,
  };
}

export function getApprovalStrategyPresentation(strategy) {
  const isAuto = strategy === 'auto';
  return {
    label: isAuto ? 'Auto' : 'Manual',
    color: isAuto ? 'success' : 'warning',
  };
}

export function getPendingExecutions(executions = []) {
  return executions.filter((execution) => execution?.status === 'pending');
}

export function toggleCredentialSelection(selectedCredentials = [], credentialId, checked) {
  if (!credentialId) {
    return [...selectedCredentials];
  }

  if (checked) {
    return selectedCredentials.includes(credentialId)
      ? [...selectedCredentials]
      : [...selectedCredentials, credentialId];
  }

  return selectedCredentials.filter((id) => id !== credentialId);
}

export function toggleAllCredentialSelections(credentials = [], checked) {
  if (!checked) {
    return [];
  }

  return credentials
    .filter((credential) => credential?.status === 'active')
    .map((credential) => credential.id)
    .filter(Boolean);
}

export function getCredentialSelectionState(credentials = [], selectedCredentials = []) {
  const selectableIds = credentials
    .filter((credential) => credential?.status === 'active')
    .map((credential) => credential.id)
    .filter(Boolean);

  const selectedSelectableCount = selectableIds.filter((id) => selectedCredentials.includes(id)).length;

  return {
    selectedCount: selectedCredentials.length,
    selectableCount: selectableIds.length,
    allSelected: selectableIds.length > 0 && selectedSelectableCount === selectableIds.length,
    partiallySelected: selectedSelectableCount > 0 && selectedSelectableCount < selectableIds.length,
  };
}

export function getBatchRevocationFeedback(strategy, selectedCount) {
  const count = Number.isFinite(selectedCount) ? selectedCount : 0;
  const immediate = strategy === 'immediate';

  return {
    severity: immediate ? 'warning' : 'success',
    message: immediate
      ? `${count} credentials revoked immediately`
      : `${count} credentials queued for batch revocation`,
  };
}

export function formatTruncatedId(value, visibleLength = 12) {
  if (!value || typeof value !== 'string') {
    return 'N/A';
  }

  return value.length > visibleLength ? `${value.substring(0, visibleLength)}...` : value;
}
