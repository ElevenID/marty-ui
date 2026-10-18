import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import IssuingSection from './IssuingSection';

vi.mock('../../issuance/OID4VCIInviteDisplay', () => ({
  default: ({ offerData }: any) => <div>Offer: {offerData.offer_url}</div>,
}));

describe('organization reviewer issuance', () => {
  it.each(['approved', 'issued'])('uses the active organization for %s applications without applicant self-claim', async (status) => {
    const requests: string[] = [];
    server.use(
      http.post('http://localhost:8000/v1/organizations/org-review/applicants/app-employee/issue', ({ request }) => {
        requests.push(request.url);
        return HttpResponse.json({ credential_offer_uri: 'openid-credential-offer://synthetic-offer' });
      }),
      http.post('http://localhost:8000/v1/me/applications/:id/claim', () => {
        throw new Error('Reviewer must never use applicant self-claim');
      }),
    );
    render(<IssuingSection organizationId="org-review" applicationId="app-employee" applicationStatus={status} />);
    fireEvent.click(screen.getByRole('button', { name: status === 'approved' ? 'Display OID4VCI Invite' : 'Generate New Wallet Invite' }));
    expect(await screen.findByText('Offer: openid-credential-offer://synthetic-offer')).toBeInTheDocument();
    expect(requests).toHaveLength(1);
  });

  it('fails closed when the active organization is missing', async () => {
    let selfClaims = 0;
    server.use(http.post('http://localhost:8000/v1/me/applications/:id/claim', () => {
      selfClaims += 1;
      return HttpResponse.json({ credential_offer_uri: 'must-not-be-used' });
    }));
    render(<IssuingSection applicationId="app-employee" applicationStatus="approved" />);
    fireEvent.click(screen.getByRole('button', { name: 'Display OID4VCI Invite' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/organization/i);
    expect(selfClaims).toBe(0);
    expect(screen.queryByText(/Offer:/)).not.toBeInTheDocument();
  });
});
