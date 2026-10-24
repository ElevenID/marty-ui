import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { createIssuerIdentity, getIssuerIdentityCapabilities, getTemplateIssuerOptions, listPublicIssuerIdentities, inspectIssuerIdentity } from '../issuerIdentitiesApi';
import * as identities from '../issuerIdentitiesApi';
import legacy, * as legacyExports from '../signingKeysApi';
import inspection from '../../../../contracts/issuer-identity-inspection-example.json';

describe('public issuer identity client', () => {
  it('lists API-advertised formats without a browser catalog or private coordinates', async () => {
    let identities = [{ ...inspection.identity, credential_format: 'FUTURE_NATIVE_FORMAT', signing_service_id: 'private-service' }];
    server.use(http.get('*/v1/signing-keys/issuer-identities', ({ request }) => {
      expect([...new URL(request.url).searchParams.keys()]).toEqual(['organization_id']);
      return HttpResponse.json({ identities });
    }));
    expect(await listPublicIssuerIdentities({ organization_id: 'org-a' })).toEqual({ identities: [{ ...inspection.identity, credential_format: 'FUTURE_NATIVE_FORMAT' }] });
    identities = [identities[0], identities[0]];
    await expect(listPublicIssuerIdentities({ organization_id: 'org-a' })).rejects.toThrow(/ambiguous/);
  });
  it('inspects only the public tuple and rejects wrong-scope, private or contradictory observations', async () => {
    let result = structuredClone(inspection) as Record<string, any>;
    const tuple = { organization_id: 'org-a', ...inspection.identity };
    server.use(http.get('*/v1/signing-keys/issuer-identities/inspection', ({ request }) => {
      const query = new URL(request.url).searchParams;
      expect([...query.keys()]).toEqual(['organization_id', 'issuer_did', 'key_purpose', 'credential_format', 'algorithm']);
      return HttpResponse.json(result);
    }));
    expect(await inspectIssuerIdentity({ ...tuple, issuer_profile_id: 'private' })).toEqual(inspection);
    for (const mutate of [
      (value: Record<string, any>) => { value.organization_id = 'other'; },
      (value: Record<string, any>) => { value.registry.document.verificationMethod[0].publicKeyJwk.d = 'private'; },
      (value: Record<string, any>) => { value.public_resolution.status = 'unavailable'; },
      (value: Record<string, any>) => { value.canonical_document_url = 'javascript:alert(1)'; },
    ]) {
      result = structuredClone(inspection); mutate(result);
      await expect(inspectIssuerIdentity(tuple)).rejects.toThrow();
    }
  });
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

  it('scopes template discovery and projects nested public bindings without custody selectors', async () => {
    let observed: unknown;
    const context = { organization_id: 'org-a', compliance_profile_id: 'profile-a',
      credential_payload_format: 'SD_JWT_VC', supported_formats: ['SD_JWT_VC'], issuance_protocol: 'OID4VCI_PRE_AUTH',
      requirements: { vct: true, doctype: false, revocation_profile: true, x509_certificate: false },
      identities: [{ issuer_did: 'did:example:issuer', bindings: [{ credential_format: 'SD_JWT_VC',
        key_purpose: 'vc_jwt_issuer', algorithm: 'ES256', key_reference: 'private' }], service_id: 'private' }],
      rejected_issuers: [{ issuer_did: 'did:example:ambiguous', reason: 'ambiguous_identity' }] };
    server.use(http.post('*/v1/credential-templates/issuer-options', async ({ request }) => {
      observed = await request.json();
      return HttpResponse.json(context);
    }));
    const result = await getTemplateIssuerOptions({ organization_id: 'org-a', compliance_profile_id: 'profile-a',
      supported_formats: ['SD_JWT_VC'], algorithm: 'ES256', key_reference: 'private' });
    expect(observed).toEqual({ organization_id: 'org-a', compliance_profile_id: 'profile-a', supported_formats: ['SD_JWT_VC'] });
    expect(JSON.stringify(result)).not.toContain('private');
    expect(result.identities[0].bindings).toEqual([{ credential_format: 'SD_JWT_VC', key_purpose: 'vc_jwt_issuer', algorithm: 'ES256' }]);
    context.organization_id = 'org-b';
    await expect(getTemplateIssuerOptions({ organization_id: 'org-a', compliance_profile_id: 'profile-a' })).rejects.toThrow(/invalid organization/);
    context.organization_id = 'org-a';
    context.rejected_issuers[0].reason = 'private-key-error';
    await expect(getTemplateIssuerOptions({ organization_id: 'org-a', compliance_profile_id: 'profile-a' })).rejects.toThrow(/invalid organization/);
  });
});


describe('public issuer lifecycle client and compatibility exports', () => {
  const tuple = { organization_id: 'org-a', issuer_did: 'did:example:issuer', key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' };
  const custody = { signing_service_id: 'forbidden', key_reference: 'forbidden', provider: 'forbidden', private_key: 'forbidden' };
  const certificate = { cert_pem: 'PUBLIC CERT', cert_chain_pem: 'PUBLIC CHAIN' };
  const subject = { country: 'US', organization: 'Example Org', common_name: 'Example Issuer' };
  const cases = [
    ['rebindIssuerIdentity', 'PATCH', '', tuple, tuple],
    ['deleteIssuerIdentity', 'DELETE', '', tuple, tuple],
    ['storeIssuerIdentityCertificate', 'PUT', '/certificate', { ...tuple, ...certificate }, { ...tuple, ...certificate }],
    ['generateIssuerIdentityCsr', 'PUT', '/certificate-csr', { ...tuple, ...subject }, { ...tuple, ...subject }],
    ['enrollCscaCertificate', 'PUT', '/csca-certificate', { ...tuple, ...certificate, certificate_id: 'csca' }, { organization_id: 'org-a', issuer_did: tuple.issuer_did, credential_format: tuple.credential_format, algorithm: 'ES256', certificate_id: 'csca', ...certificate }],
    ['issueCscaSelfSignedCertificate', 'POST', '/csca-self-signed-certificate', { ...tuple, ...subject, certificate_id: 'csca', validity_days: 30 }, { issuer_did: tuple.issuer_did, certificate_id: 'csca', credential_format: 'ICAO_EMRTD', ...subject, validity_days: 30 }],
    ['issueDscCertificate', 'POST', '/dsc-certificate', { ...tuple, ...subject, dsc_issuer_did: 'did:example:dsc', csca_issuer_did: 'did:example:csca', csca_certificate_id: 'csca', validity_days: 30, idempotency_key: 'request-id' }, { dsc_issuer_did: 'did:example:dsc', csca_issuer_did: 'did:example:csca', csca_certificate_id: 'csca', credential_format: 'ICAO_EMRTD', ...subject, validity_days: 30, idempotency_key: 'request-id' }],
  ] as const;
  it.each(cases)('%s preserves the public wire contract without accepting custody selectors', async (name, method, suffix, input, body) => {
    let observed: unknown;
    server.use(http.all('*/v1/signing-keys/issuer-identities*', async ({ request }) => {
      const url = new URL(request.url);
      observed = { method: request.method, path: url.pathname, query: [...url.searchParams], body: await request.json() };
      return HttpResponse.json({ ok: true });
    }));
    await identities[name]({ ...input, ...custody });
    expect(observed).toEqual({ method, path: '/v1/signing-keys/issuer-identities' + suffix,
      query: method === 'POST' ? [['organization_id', 'org-a']] : [], body });
    expect(legacyExports[name]).toBe(identities[name]);
    expect(legacy[name]).toBe(identities[name]);
  });
  it.each(['getOrgJwks', 'getOrgDidDocument'] as const)('%s requires explicit scope for public documents and preserves old callers', async (name) => {
    let observed: string | undefined;
    server.use(http.get('*/v1/signing-keys/*', ({ request }) => { observed = request.url; return HttpResponse.json({ public: true }); }));
    await expect(identities[name]()).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    expect(await identities[name]('org/a')).toEqual({ public: true });
    const url = new URL(observed!);
    expect(url.pathname).toBe('/v1/signing-keys/' + (name === 'getOrgJwks' ? 'jwks' : 'did-document'));
    expect([...url.searchParams]).toEqual([['organization_id', 'org/a']]);
    expect(legacyExports[name]).toBe(identities[name]);
    expect(legacy[name]).toBe(identities[name]);
  });
});
