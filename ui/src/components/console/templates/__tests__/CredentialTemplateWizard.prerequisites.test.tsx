import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes, useLocation } from 'react-router';
import { http, HttpResponse } from 'msw';
import { renderWithRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import CredentialTemplateWizard from '../CredentialTemplateWizard';

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { user_id: 'template-author' } }),
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}));

const wizardPath = '/console/org/templates/credentials/new';

function WizardRoutes() {
  const location = useLocation();
  return <>
    <output data-testid="current-route">{location.pathname}</output>
    <Routes>
      <Route path={wizardPath} element={<CredentialTemplateWizard />} />
      <Route path="/console/org/trust/profiles/new" element={<h1>New Trust Profile</h1>} />
      <Route path="/console/org/deploy/issuer-identity/new" element={<h1>New issuer identity</h1>} />
    </Routes>
  </>;
}

beforeEach(() => {
  server.use(
    http.get('*/v1/organizations/:organizationId/defaults', () => HttpResponse.json({})),
    http.get('*/v1/trust-profiles', () => HttpResponse.json([])),
    http.get('*/v1/compliance-profiles', () => HttpResponse.json([])),
  );
});

describe('CredentialTemplateWizard prerequisite links', () => {
  it.each([
    ['Create Trust Profile', '/console/org/trust/profiles/new'],
    ['Create issuer identity', '/console/org/deploy/issuer-identity/new'],
  ])('keeps the current step and typed draft when opening %s', async (label, destination) => {
    const { user } = renderWithRouter(<WizardRoutes />, { initialEntries: [wizardPath] });
    await user.type(screen.getByLabelText(/Template Name/i), 'Prerequisite recovery draft');
    await user.type(screen.getByLabelText(/Description/i), 'Keep this description while configuring prerequisites.');
    await user.type(screen.getByLabelText(/VCT/i), 'urn:example:prerequisite-recovery');
    await user.click(screen.getByTestId('wizard.template.next'));
    await user.type(screen.getByLabelText('Claim Name'), 'member_reference');
    await user.click(screen.getByRole('button', { name: 'Add' }));
    await user.click(screen.getByTestId('wizard.template.next'));
    await screen.findByText(/Trust profile required/);

    await user.click(screen.getByText(label));

    expect(screen.getByTestId('current-route')).toHaveTextContent(wizardPath);
    expect(screen.getByRole('button', { name: 'Refresh profiles' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh issuer compatibility' })).toBeInTheDocument();
    const link = screen.getByRole('link', { name: `${label} (opens in a new tab)` });
    expect(link).toHaveAttribute('href', destination);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');

    await user.click(screen.getByTestId('wizard.template.back'));
    expect(screen.getByText('member_reference')).toBeInTheDocument();
    await user.click(screen.getByTestId('wizard.template.back'));
    expect(screen.getByLabelText(/Template Name/i)).toHaveValue('Prerequisite recovery draft');
    expect(screen.getByLabelText(/Description/i)).toHaveValue('Keep this description while configuring prerequisites.');
    expect(screen.getByLabelText(/VCT/i)).toHaveValue('urn:example:prerequisite-recovery');
  });
});
