import { describe, expect, it } from 'vitest';
import { render, screen } from '@test/utils';
import { SystemStatusBar } from './SystemStatusBar';

describe('SystemStatusBar', () => {
  it('identifies the measured issuance service and explains an unreported verifier', async () => {
    const { user } = render(<SystemStatusBar systemHealth={{ gateway: 'healthy', issuer: 'healthy', verifier: 'unknown' }} />);
    expect(screen.getByText('Issuance Service')).toBeInTheDocument();
    expect(screen.queryByText('Issuer Metadata')).not.toBeInTheDocument();
    expect(screen.getAllByText('Healthy')).toHaveLength(2);
    await user.hover(screen.getByText('Unknown'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('This service was not reported by the latest readiness check.');
  });
});
