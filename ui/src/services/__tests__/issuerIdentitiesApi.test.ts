import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { createIssuerIdentity, getIssuerIdentityCapabilities } from '../issuerIdentitiesApi';

describe('public issuer identity client', () => {
  it('requires an explicit organization before discovery or creation', async () => {
    await expect(getIssuerIdentityCapabilities()).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    await expect(createIssuerIdentity({ issuer_did: 'did:example:issuer' })).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
  });

  it('rejects another organization response and projects only public capability fields', async () => {
    let organization = 'other';
    server.use(http.get('*/v1/signing-keys/issuer-identities/capabilities', ({ request }) => {
      expect(new URL(request.url).searchParams.get('organization_id')).toBe('org-a');
      return HttpResponse.json({ organization_id: organization, managed_issuer_did_prefix: 'did:web:issuer.example:orgs:',
        basis: 'configuration', service_id: 'must-not-leak', creation_options: [{ key_purpose: 'vc_jwt_issuer',
          credential_format: 'SD_JWT_VC', algorithm: 'ES256', key_reference: 'must-not-leak' }] });
    }));
    await expect(getIssuerIdentityCapabilities({ organization_id: 'org-a' })).rejects.toThrow(/invalid organization/);
    organization = 'org-a';
    expect(await getIssuerIdentityCapabilities({ organization_id: ' org-a ' })).toEqual({
      organization_id: 'org-a', managed_issuer_did_prefix: 'did:web:issuer.example:orgs:', basis: 'configuration',
      creation_options: [{ key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' }],
    });
  });

  it('sends public identity intent without spreading caller custody fields', async () => {
    let observed: unknown;
    server.use(http.post('*/v1/signing-keys/issuer-identities', async ({ request }) => {
      observed = await request.json();
      return HttpResponse.json({ created: true });
    }));
    await createIssuerIdentity({ organization_id: 'org-a', issuer_did: 'did:web:issuer.example:orgs:a',
      key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256',
      signing_service_id: 'forbidden', key_reference: 'forbidden', kms_provider: 'forbidden' });
    expect(observed).toEqual({ organization_id: 'org-a', issuer_did: 'did:web:issuer.example:orgs:a',
      key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' });
  });
});
