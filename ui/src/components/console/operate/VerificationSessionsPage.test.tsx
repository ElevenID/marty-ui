import { describe, expect, it, vi } from 'vitest';
import { screen, renderWithRouter } from '@test/utils';

import VerificationSessionsPage from './VerificationSessionsPage';

vi.mock('../../vendor/verification/VerificationSessionManager', () => ({
  default: () => <div data-testid="oid4vp-session-manager">OID4VP session manager</div>,
}));

vi.mock('../../canvas/CanvasMirrorProvenanceLookup', () => ({
  default: ({ organizationId, showOrganizationField, title, initialParams }) => (
    <div data-testid="canvas-provenance-lookup">
      {title} {organizationId} {String(showOrganizationField)} {initialParams?.externalCredentialId || ''}
    </div>
  ),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));

describe('VerificationSessionsPage', () => {
  it('keeps OID4VP sessions primary and exposes Canvas provenance as a support lookup', async () => {
    const { user } = renderWithRouter(<VerificationSessionsPage />, {
      initialEntries: ['/console/org/operate/verify'],
    });

    expect(screen.getByTestId('oid4vp-session-manager')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: /canvas provenance/i }));

    expect(screen.getByTestId('verification-canvas-provenance-section')).toBeInTheDocument();
    expect(screen.getByText(/employer-facing verification should use an oid4vp session/i)).toBeInTheDocument();
    expect(screen.getByTestId('canvas-provenance-lookup')).toHaveTextContent('Canvas mirror provenance org-1 false');
  });

  it('opens Canvas provenance directly when a Canvas credential lookup is provided', async () => {
    renderWithRouter(<VerificationSessionsPage />, {
      initialEntries: ['/console/org/operate/verify?external_credential_id=canvas-cred-1&canvas_account_id=account-1'],
    });

    expect(screen.queryByTestId('oid4vp-session-manager')).not.toBeInTheDocument();
    expect(screen.getByTestId('verification-canvas-provenance-section')).toBeInTheDocument();
    expect(screen.getByTestId('canvas-provenance-lookup')).toHaveTextContent('canvas-cred-1');
  });
});
