import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';
import PublicFooter from './PublicFooter';

vi.mock('@ui-public-config', () => ({ IS_SELFHOST_UI: true, SHOW_PUBLIC_DEMOS: false }));

describe('customer public footer', () => {
  it('does not render production legal, marketing, or sales destinations', () => {
    render(<PublicFooter />);
    expect(screen.queryByTestId('public-footer')).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});
