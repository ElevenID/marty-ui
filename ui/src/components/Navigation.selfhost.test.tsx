import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';
import Navigation from './Navigation';

vi.mock('@ui-public-config', async () => import('../variants/publicConfig.selfhost'));
vi.mock('../hooks/useAuth', () => ({ useAuth: () => ({ isAuthenticated: false }) }));

afterEach(() => {
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
});

describe('customer navigation', () => {
  it('offers application destinations without marketing navigation', () => {
    render(<Navigation />);
    expect(screen.getByRole('tab', { name: 'Console' })).toHaveAttribute('href', '/console');
    expect(screen.getByRole('tab', { name: 'Applications' })).toHaveAttribute('href', '/apply');
    expect(screen.queryByRole('tab', { name: 'Product' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Pricing' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Start Verifying' })).not.toBeInTheDocument();
  });

  it('removes navigation to a console excluded at startup', () => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: ['public'] } };
    render(<Navigation />);
    expect(screen.queryByRole('tab', { name: 'Console' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Applications' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Home' })).toBeVisible();
  });
});
