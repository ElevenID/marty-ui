import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';
import OpenBadgesIssuancePage from './OpenBadgesIssuancePage';

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn() }));
vi.mock('../../application/routing/useSurfaceNavigate', () => ({ useSurfaceNavigate: () => navigate }));
vi.mock('../seo', () => ({ SEOHead: () => null, softwareApplicationSchema: () => ({}) }));

describe('Open Badges issuance entry', () => {
  beforeEach(() => vi.clearAllMocks());

  it('explains prerequisites and sends setup through the authenticated template route', async () => {
    const { user } = render(<OpenBadgesIssuancePage />);
    expect(screen.getByRole('alert')).toHaveTextContent('Sign in to an organization');
    expect(screen.getByRole('alert')).toHaveTextContent('synthetic learner data');
    await user.click(screen.getByRole('button', { name: 'Set up a badge workflow' }));
    expect(navigate).toHaveBeenLastCalledWith('/console/org/templates/credentials/new');
    await user.click(screen.getByRole('button', { name: 'Review demo evidence' }));
    expect(navigate).toHaveBeenLastCalledWith('/demos');
    expect(screen.getByText(/Check that evidence separately from your own deployment's results/)).toBeInTheDocument();
  });
});
