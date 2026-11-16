/**
 * Pure helpers for the vendor flow management console.
 */

export function getFlowStatusPresentation(status) {
  const normalizedStatus = typeof status === 'string' ? status.trim().toUpperCase() : '';
  const presentation = {
    DRAFT: { label: 'Draft', color: 'default', icon: 'warning' },
    ACTIVE: { label: 'Active', color: 'success', icon: 'success' },
    PAUSED: { label: 'Paused', color: 'warning', icon: 'warning' },
    ARCHIVED: { label: 'Archived', color: 'default', icon: null },
  }[normalizedStatus] || { label: 'Unknown', color: 'default', icon: null };
  return {
    status: normalizedStatus || 'UNKNOWN',
    ...presentation,
    isDraft: normalizedStatus === 'DRAFT',
    isActive: normalizedStatus === 'ACTIVE',
  };
}

export function getApprovalStrategyPresentation(strategy) {
  const normalizedStrategy = typeof strategy === 'string' ? strategy.trim().toUpperCase() : '';
  return {
    AUTO: { label: 'Auto', color: 'success' },
    MANUAL: { label: 'Manual', color: 'warning' },
    RULES_BASED: { label: 'Rules based', color: 'info' },
    EXTERNAL: { label: 'External', color: 'info' },
  }[normalizedStrategy] || { label: 'Unknown', color: 'default' };
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
