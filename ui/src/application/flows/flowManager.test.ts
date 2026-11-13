import { describe, expect, it } from 'vitest';

import {
  formatTruncatedId,
  getApprovalStrategyPresentation,
  getBatchRevocationFeedback,
  getCredentialSelectionState,
  getFlowStatusPresentation,
  getPendingExecutions,
  toggleAllCredentialSelections,
  toggleCredentialSelection,
} from './flowManager';

describe('flowManager helpers', () => {
  it.each([
    ['DRAFT', 'Draft', 'default', true, false],
    ['ACTIVE', 'Active', 'success', false, true],
    ['PAUSED', 'Paused', 'warning', false, false],
    ['ARCHIVED', 'Archived', 'default', false, false],
    [' active ', 'Active', 'success', false, true],
  ])('shows native lifecycle status %s without inferring publication', (status, label, color, isDraft, isActive) => {
    const presentation = getFlowStatusPresentation(status);
    expect(presentation).toMatchObject({ label, color, isDraft, isActive });
    expect(presentation).not.toHaveProperty('isPublished');
    expect(presentation).not.toHaveProperty('hasApplicantEntry');
  });

  it.each([undefined, null, '', 'PUBLISHED', 'unexpected'])('does not invent a lifecycle state for %s', (status) => {
    expect(getFlowStatusPresentation(status)).toMatchObject({
      label: 'Unknown', color: 'default', isDraft: false, isActive: false,
    });
  });

  it.each([
    ['AUTO', 'Auto', 'success'],
    ['MANUAL', 'Manual', 'warning'],
    ['RULES_BASED', 'Rules based', 'info'],
    ['EXTERNAL', 'External', 'info'],
    [' auto ', 'Auto', 'success'],
    ['manual', 'Manual', 'warning'],
    [undefined, 'Unknown', 'default'],
    ['unexpected', 'Unknown', 'default'],
  ])('shows authoritative approval mode %s', (strategy, label, color) => {
    expect(getApprovalStrategyPresentation(strategy)).toEqual({ label, color });
  });

  it('filters pending executions', () => {
    expect(getPendingExecutions([
      { id: '1', status: 'pending' },
      { id: '2', status: 'completed' },
      { id: '3', status: 'pending' },
    ])).toEqual([
      { id: '1', status: 'pending' },
      { id: '3', status: 'pending' },
    ]);
  });

  it('toggles individual credential selection', () => {
    expect(toggleCredentialSelection(['cred-1'], 'cred-2', true)).toEqual(['cred-1', 'cred-2']);
    expect(toggleCredentialSelection(['cred-1', 'cred-2'], 'cred-2', false)).toEqual(['cred-1']);
  });

  it('toggles all selectable credentials', () => {
    const credentials = [
      { id: 'cred-1', status: 'active' },
      { id: 'cred-2', status: 'revoked' },
      { id: 'cred-3', status: 'active' },
    ];

    expect(toggleAllCredentialSelections(credentials, true)).toEqual(['cred-1', 'cred-3']);
    expect(toggleAllCredentialSelections(credentials, false)).toEqual([]);
  });

  it('derives aggregate credential selection state', () => {
    const credentials = [
      { id: 'cred-1', status: 'active' },
      { id: 'cred-2', status: 'revoked' },
      { id: 'cred-3', status: 'active' },
    ];

    expect(getCredentialSelectionState(credentials, ['cred-1'])).toEqual({
      selectedCount: 1,
      selectableCount: 2,
      allSelected: false,
      partiallySelected: true,
    });
  });

  it('builds batch revocation feedback', () => {
    expect(getBatchRevocationFeedback('immediate', 2)).toEqual({
      severity: 'warning',
      message: '2 credentials revoked immediately',
    });

    expect(getBatchRevocationFeedback('scheduled', 3)).toEqual({
      severity: 'success',
      message: '3 credentials queued for batch revocation',
    });
  });

  it('formats truncated identifiers safely', () => {
    expect(formatTruncatedId('abcdefghijklmnop')).toBe('abcdefghijkl...');
    expect(formatTruncatedId('short')).toBe('short');
    expect(formatTruncatedId(null as unknown as string)).toBe('N/A');
  });
});
