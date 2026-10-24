import { useCallback, useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import TrustComplianceStep from '../steps/TrustComplianceStep';
import { validTemplateIssuerSelection } from '../templateIssuerSelection';
const { scope } = vi.hoisted(() => ({ scope: { activeOrgId: 'org-a' } }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.activeOrgId }) }));
const options = (org = 'org-a', compliance = 'compliance-sd') => {
  const mdoc = compliance === 'compliance-mdoc';
  return { organization_id: org, compliance_profile_id: compliance,
    credential_payload_format: mdoc ? 'MDOC' : 'SD_JWT_VC', supported_formats: [mdoc ? 'MDOC' : 'SD_JWT_VC'],
    issuance_protocol: 'OID4VCI_PRE_AUTH', requirements: { vct: !mdoc, doctype: mdoc, revocation_profile: true, x509_certificate: false },
    identities: [{ issuer_did: `did:example:${org}-${mdoc ? 'mdoc' : 'sd'}`, bindings: [{ credential_format: mdoc ? 'MDOC' : 'SD_JWT_VC', key_purpose: mdoc ? 'mdoc_dsc' : 'vc_jwt_issuer', algorithm: 'ES256' }] }], rejected_issuers: [] };
};
function Stateful() {
  const [data, setData] = useState<Record<string, any>>({ trust_profile_id: 'trust-1', compliance_profile_id: 'compliance-sd', vct: 'urn:example:employee' });
  const update = useCallback((patch: Record<string, unknown>) => setData((previous) => ({ ...previous, ...patch })), []);
  return <><TrustComplianceStep data={data} onChange={update} /><output data-testid="ready">{String(validTemplateIssuerSelection(data, scope.activeOrgId))}</output><output data-testid="state">{JSON.stringify(data)}</output></>;
}
async function selectIssuer(user: ReturnType<typeof renderWithRouter>['user'], value: string) {
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Issuer DID' })).not.toHaveAttribute('aria-disabled', 'true'));
  await user.click(screen.getByRole('combobox', { name: 'Issuer DID' }));
  await user.click(await screen.findByRole('option', { name: value }));
}
beforeEach(() => {
  scope.activeOrgId = 'org-a';
  server.use(
    http.get('*/v1/trust-profiles', ({ request }) => HttpResponse.json([{ id: 'trust-1', organization_id: new URL(request.url).searchParams.get('organization_id'), name: 'Trust One', status: 'active' }])),
    http.get('*/v1/compliance-profiles', () => HttpResponse.json([
      { id: 'compliance-sd', name: 'SD Profile', is_system: true, status: 'ACTIVE', credential_format: 'SD_JWT_VC', discoverable: true },
      { id: 'compliance-mdoc', name: 'Document Profile', is_system: true, status: 'ACTIVE', credential_format: 'MDOC', discoverable: true },
      { id: 'inactive', name: 'Inactive System Profile', is_system: true, status: 'SUSPENDED', credential_format: 'SD_JWT_VC' },
      { id: 'foreign', name: 'Other Tenant Profile', organization_id: 'foreign-org', is_system: true, status: 'ACTIVE', credential_format: 'SD_JWT_VC' },
    ])),
    http.post('*/v1/credential-templates/issuer-options', async ({ request }) => {
      const body = await request.json() as Record<string, string>;
      expect(body).not.toHaveProperty('algorithm'); expect(body).not.toHaveProperty('issuer_profile_id');
      return HttpResponse.json(options(body.organization_id, body.compliance_profile_id));
    }),
  );
});
describe('TrustComplianceStep uses public API contracts', () => {
  it('offers compatible DIDs only after active authorized profile discovery', async () => {
    const { user } = renderWithRouter(<Stateful />);
    await selectIssuer(user, 'did:example:org-a-sd');
    await waitFor(() => expect(screen.getByTestId('ready')).toHaveTextContent('true'));
    expect(screen.getByTestId('state')).toHaveTextContent('SD_JWT_VC');
    await user.click(screen.getByRole('combobox', { name: 'Compliance Profile' }));
    expect(screen.queryByRole('option', { name: 'Inactive System Profile' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Other Tenant Profile' })).not.toBeInTheDocument();
  });
  it('clears an old DID and derives doctype requirements when the profile changes', async () => {
    const { user } = renderWithRouter(<Stateful />);
    await selectIssuer(user, 'did:example:org-a-sd');
    await waitFor(() => expect(screen.getByTestId('ready')).toHaveTextContent('true'));
    await user.click(screen.getByRole('combobox', { name: 'Compliance Profile' }));
    await user.click(screen.getByRole('option', { name: 'Document Profile' }));
    await waitFor(() => expect(screen.getByTestId('ready')).toHaveTextContent('false'));
    await selectIssuer(user, 'did:example:org-a-mdoc');
    expect(screen.getByTestId('ready')).toHaveTextContent('false');
    await user.type(await screen.findByLabelText(/Document type/), 'org.example.document');
    await waitFor(() => expect(screen.getByTestId('ready')).toHaveTextContent('true'));
    expect(screen.queryByLabelText(/Credential type URI/)).not.toBeInTheDocument();
  });
  it('keeps profile choices available when ambiguous bindings leave no selectable DID', async () => {
    server.use(http.post('*/v1/credential-templates/issuer-options', () => HttpResponse.json({ ...options(), identities: [], rejected_issuers: [{ issuer_did: 'did:example:ambiguous', reason: 'ambiguous_identity' }] })));
    renderWithRouter(<Stateful />);
    expect(await screen.findByText(/ambiguous registry bindings/)).toBeInTheDocument();
    expect(screen.getByTestId('ready')).toHaveTextContent('false');
    expect(screen.getByRole('combobox', { name: 'Compliance Profile' })).not.toHaveAttribute('aria-disabled', 'true');
  });
  it('fails closed on discovery failure and supports explicit retry', async () => {
    let failed = true;
    server.use(http.post('*/v1/credential-templates/issuer-options', () => failed ? HttpResponse.json({ detail: 'unavailable' }, { status: 422 }) : HttpResponse.json(options())));
    const { user } = renderWithRouter(<Stateful />);
    expect(await screen.findByText(/Issuer compatibility could not be checked/)).toBeInTheDocument();
    expect(screen.getByTestId('ready')).toHaveTextContent('false'); failed = false;
    await user.click(screen.getByRole('button', { name: 'Refresh issuer compatibility' }));
    await selectIssuer(user, 'did:example:org-a-sd');
    await waitFor(() => expect(screen.getByTestId('ready')).toHaveTextContent('true'));
  });
  it('rejects another organization response', async () => {
    server.use(http.post('*/v1/credential-templates/issuer-options', () => HttpResponse.json(options('other-org'))));
    renderWithRouter(<Stateful />);
    expect(await screen.findByText(/invalid organization or compatibility data/)).toBeInTheDocument();
    expect(screen.getByTestId('ready')).toHaveTextContent('false');
  });
  it('ignores late responses after the organization changes', async () => {
    let releaseOld!: () => void;
    const pending = new Promise<void>((resolve) => { releaseOld = resolve; });
    server.use(http.post('*/v1/credential-templates/issuer-options', async ({ request }) => {
      const body = await request.json() as Record<string, string>;
      if (body.organization_id === 'org-a') await pending;
      return HttpResponse.json(options(body.organization_id));
    }));
    const view = renderWithRouter(<Stateful />);
    await screen.findByLabelText('Checking issuer compatibility');
    scope.activeOrgId = 'org-b'; view.rerender(<Stateful />);
    await selectIssuer(view.user, 'did:example:org-b-sd');
    await waitFor(() => expect(screen.getByTestId('ready')).toHaveTextContent('true'));
    await act(async () => { releaseOld(); await pending; });
    expect(screen.getByTestId('state')).toHaveTextContent('did:example:org-b-sd');
    expect(screen.getByTestId('state')).not.toHaveTextContent('did:example:org-a-sd');
  });
});
