import { describe, expect, it } from 'vitest';
import { render, screen } from '@test/utils';
import { CriticalEventsPanel } from './CriticalEventsPanel';

describe('CriticalEventsPanel', () => {
  it('reports an empty audit result without declaring the system healthy', () => {
    render(<CriticalEventsPanel events={[]} />);
    expect(screen.getByRole('alert')).toHaveTextContent('No critical events were reported in the last 24 hours.');
    expect(screen.queryByText(/all systems operating normally/i)).not.toBeInTheDocument();
    expect(screen.queryByTestId('CheckCircleIcon')).not.toBeInTheDocument();
  });

  it('shows an audit failure instead of treating an unavailable feed as empty', () => {
    render(<CriticalEventsPanel events={[]} error={new Error('Audit service unavailable')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Critical events unavailable');
    expect(screen.getByRole('alert')).toHaveTextContent('Audit service unavailable');
    expect(screen.queryByText(/No critical events were reported/i)).not.toBeInTheDocument();
  });
});
