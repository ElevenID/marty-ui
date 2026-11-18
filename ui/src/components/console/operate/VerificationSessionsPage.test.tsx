import { describe, expect, it, vi } from 'vitest';
import { screen, renderWithRouter, within } from '@test/utils';

import VerificationSessionsPage from './VerificationSessionsPage';

vi.mock('../../vendor/verification/VerificationSessionManager', () => ({
  default: ({ organizationId }) => <div data-testid="oid4vp-session-manager">OID4VP session manager {organizationId}</div>,
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}));

describe('VerificationSessionsPage', () => {
  it('renders organization-scoped OID4VP sessions and operation navigation', () => {
    renderWithRouter(<VerificationSessionsPage />, {
      initialEntries: ['/console/org/operate/verify'],
    });

    expect(screen.getByTestId('oid4vp-session-manager')).toHaveTextContent('org-1');
    const tabs = within(screen.getAllByRole('tablist')[0]).getAllByRole('tab');
    expect(tabs.map(tab => tab.textContent)).toEqual([
      'Flow Instances', 'Applications', 'Issued Credentials', 'Verification sessions',
    ]);
    expect(tabs[3]).toHaveAttribute('aria-selected', 'true');

  });

  it('ignores retired provider lookup parameters and keeps canonical verification available', () => {
    renderWithRouter(<VerificationSessionsPage />, {
      initialEntries: ['/console/org/operate/verify?external_credential_id=canvas-cred-1&canvas_account_id=account-1'],
    });

    expect(screen.getByTestId('oid4vp-session-manager')).toHaveTextContent('org-1');
    expect(screen.queryByRole('tab', { name: /canvas provenance/i })).not.toBeInTheDocument();
  });
});
