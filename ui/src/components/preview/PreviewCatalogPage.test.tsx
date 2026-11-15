import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Link, Route, Routes } from 'react-router';
import { renderWithRouter, screen, within } from '@test/utils';
import PreviewCatalogPage from './PreviewCatalogPage';

const { auth, get } = vi.hoisted(() => ({
  auth: { organizationId: 'org-1', organizationName: 'Current organization', user: { user_id: 'person-1' } },
  get: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../services/api', () => ({ get }));
vi.mock('../../services/applicantApi', () => ({ listApplications: async () => ({ items: [], total: 0 }) }));

function page() {
  return <>
    <Link to="/applicant/preview/catalog?organization_id=org-1&view=again">Reopen catalog</Link>
    <Routes>
      <Route path="/applicant/preview/catalog" element={<PreviewCatalogPage />} />
    </Routes>
  </>;
}

describe('PreviewCatalogPage route and account lifetime', () => {
  beforeEach(() => {
    get.mockReset();
    auth.user = { user_id: 'person-1' };
    get.mockImplementation(async (endpoint: string) => {
      if (endpoint.includes('/v1/credential-templates')) return [{
        id: 'credential-1', name: 'Membership credential', credential_type: 'MemberCredential', claims: [],
        status: 'ACTIVE', revocation_profile_id: 'revocation-1',
      }];
      if (endpoint.includes('/v1/application-templates')) return [{
        id: 'application-1', credential_template_id: 'credential-1', organization_id: 'org-1', status: 'ACTIVE',
      }];
      return [];
    });
  });

  it('starts a fresh catalog view when the same organization opens in a new Router entry', async () => {
    const { user } = renderWithRouter(page(), { initialEntries: ['/applicant/preview/catalog?organization_id=org-1'] });
    await screen.findByTestId('credential-card-credential-1');
    await user.type(within(screen.getByTestId('credential-search')).getByRole('textbox'), 'No matching credential');
    expect(screen.queryByTestId('credential-card-credential-1')).not.toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Reopen catalog' }));
    expect(await screen.findByTestId('credential-card-credential-1')).toBeInTheDocument();
    expect(within(screen.getByTestId('credential-search')).getByRole('textbox')).toHaveValue('');
  });

  it('starts a fresh catalog view when the authenticated account changes', async () => {
    const { user, rerender } = renderWithRouter(page(), { initialEntries: ['/applicant/preview/catalog?organization_id=org-1'] });
    await screen.findByTestId('credential-card-credential-1');
    await user.type(within(screen.getByTestId('credential-search')).getByRole('textbox'), 'Previous account filter');
    auth.user = { user_id: 'person-2' };
    rerender(page());
    expect(await screen.findByTestId('credential-card-credential-1')).toBeInTheDocument();
    expect(within(screen.getByTestId('credential-search')).getByRole('textbox')).toHaveValue('');
  });
});
