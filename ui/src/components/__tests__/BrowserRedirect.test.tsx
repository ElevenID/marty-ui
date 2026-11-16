import { describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen } from '@test/utils';
import BrowserRedirect from '../BrowserRedirect';
import { redirectBrowser } from '../../application/routing/appHandoff';

vi.mock('../../application/routing/appHandoff', () => ({
  redirectBrowser: vi.fn(),
}));

describe('BrowserRedirect', () => {
  it('keeps the handoff state centered while preserving the destination query', () => {
    renderWithRouter(
      <BrowserRedirect to="/console/applicant/catalog" preserveSearch message="Opening catalog..." />,
      { initialEntries: ['/catalog?organization_id=org-1'] },
    );

    const loadingState = screen.getByTestId('browser-redirect');
    expect(screen.getByText('Opening catalog...')).toBeVisible();
    expect(screen.getByRole('progressbar')).toBeVisible();
    expect(loadingState).toHaveStyle({
      display: 'flex',
      'flex-direction': 'column',
      'align-items': 'center',
      'justify-content': 'center',
      'min-height': `${window.innerHeight / 2}px`,
    });
    for (const attribute of ['display', 'flexDirection', 'alignItems', 'justifyContent', 'minHeight']) {
      expect(loadingState).not.toHaveAttribute(attribute);
    }
    expect(redirectBrowser).toHaveBeenCalledWith('/console/applicant/catalog?organization_id=org-1', { replace: true });
  });
});
