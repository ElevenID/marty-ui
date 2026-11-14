import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithoutRouter } from '../../test/utils';
import StatusChip from './StatusChip';
import flowContract from '../../../../contracts/flow-service-behavior.json';

const nativeFlowLabels: Record<string, string> = {
  PENDING: 'Pending', IN_PROGRESS: 'In progress', AWAITING_WALLET: 'Awaiting wallet',
  AWAITING_APPROVAL: 'Awaiting approval', AWAITING_EVIDENCE: 'Awaiting evidence',
  COMPLETED: 'Completed', FAILED: 'Failed', CANCELLED: 'Cancelled', EXPIRED: 'Expired',
};

describe('StatusChip', () => {
  it.each([
    ['ACTIVE', 'Active'],
    [' suspended ', 'Suspended'],
    ['REVOKED', 'Revoked'],
  ])('normalizes the lifecycle status %s', (status, label) => {
    renderWithoutRouter(<StatusChip status={status} showIcon />);

    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
  });

  it.each([
    ['observed', 'Observed'],
    ['identity_link_required', 'Identity Link Required'],
    ['eligible', 'Eligible'],
    ['pending_claim', 'Awaiting Wallet Claim'],
    ['claimed', 'Claimed'],
    ['dismissed', 'Dismissed'],
    ['queued', 'Queued'],
    ['leased', 'Processing'],
    ['retry', 'Retry Scheduled'],
    ['succeeded', 'Succeeded'],
    ['dead_letter', 'Needs Intervention'],
    ['cancelled', 'Cancelled'],
  ])('renders the Canvas state %s without implying issuance or success', (status, label) => {
    renderWithoutRouter(<StatusChip status={status} showIcon />);
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
  });

  it.each([...new Set(Object.values(flowContract.status_projection))])('renders the native public Flow status %s', (status) => {
    expect(nativeFlowLabels[status]).toBeDefined();
    renderWithoutRouter(<StatusChip status={status} showIcon />);
    expect(screen.getByText(nativeFlowLabels[status])).toBeInTheDocument();
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
    if (status === 'PENDING') expect(screen.queryByText('Running')).not.toBeInTheDocument();
  });

  it.each(['future_flow_state', 'constructor', '__proto__', '', 'CREATED'])('keeps an unrecognized public status %s unknown', (status) => {
    renderWithoutRouter(<StatusChip status={status} showIcon />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.queryByTestId('CheckCircleIcon')).not.toBeInTheDocument();
  });
});
