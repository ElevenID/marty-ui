import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithoutRouter } from '../../test/utils';
import StatusChip from './StatusChip';

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
});
