import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { saveWalletIssuerTrust, updateTrustProfile } from '../presentationPolicyApi';

const ORG = 'org-wallet';
const PROFILE = 'profile-wallet';
const ISSUER = 'issuer-wallet';
const DID = 'did:web:issuer.example.test:wallet';
const VCT = 'https://types.example.test/WalletDemo';
const JWK = { ...generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }), use: 'sig', alg: 'ES256', kid: `${DID}#key-1` };
const NOW = '2026-11-26T12:00:00Z';
const grants = [{ format: 'SD_JWT_VC', vct: VCT }];
const issuance = [{ credential_issuer: 'https://issuer.example.test/org/demo', credential_configuration_id: 'wallet-demo', format: 'dc+sd-jwt', vct: VCT, authorization_server: null, token_endpoint: null }];
let profile: any;
let issuer: any;
let relationship: any;
let writes: Array<{ path: string; body: any; credentials: string; headers: Headers }>;
// Match the native owner's strip_nulls public serializer, including array nulls.
const nativeResponse = (value: any): any => Array.isArray(value) ? value.map(nativeResponse)
  : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value)
    .filter(([, item]) => item !== null).map(([name, item]) => [name, nativeResponse(item)])) : value;

function input(existing = true) {
  return {
    profile_updated_at: NOW,
    issuer: existing ? structuredClone(issuer) : { issuer_id: DID, display_name: 'Demo issuer' },
    relationship: existing ? structuredClone(relationship) : null,
    verification_keys: [JWK], credential_types: [VCT], issuance_authorizations: issuance,
  };
}
async function record(request: Request) {
  const body = await request.json();
  writes.push({ path: new URL(request.url).pathname, body, credentials: request.credentials, headers: request.headers });
  return body;
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  writes = [];
  profile = { id: PROFILE, organization_id: ORG, profile_type: 'CUSTOM', status: 'draft', updated_at: NOW,
    trust_purposes: ['CREDENTIAL_ISSUER'], trust_sources: [], allowed_issuers: ['did:web:retained.example'], compliance_status: 'SETUP_REQUIRED',
    revocation_policy: { check_mode: 'HARD_FAIL', cache_ttl_seconds: 3600 },
    revocation_services: { enabled_methods: [], auto_discover: false, merge_discovered: false } };
  issuer = { id: ISSUER, organization_id: ORG, issuer_id: DID, display_name: 'Demo issuer', updated_at: NOW,
    compliance_status: 'COMPLIANT', metadata: { retained_annotation: { source: 'owner' }, verification_keys: [JWK] } };
  relationship = { id: 'relationship-wallet', trust_profile_id: PROFILE, issuer_id: ISSUER, updated_at: NOW,
    trust_level: 70, relationship_status: 'TRUSTED', cascade_revocation_policy: 'NOTIFY_ONLY',
    metadata: { retained_annotation: ['keep', null], marty_credential_authorizations_v1: [], marty_wallet_issuance_authorizations_v1: [] } };
  server.use(
    http.get(`*/v1/trust-profiles/${PROFILE}`, () => HttpResponse.json(profile)),
    http.get('*/v1/issuer-entities', () => HttpResponse.json(issuer ? [issuer] : [])),
    http.get(`*/v1/issuer-entities/${ISSUER}`, () => HttpResponse.json(issuer)),
    http.get(`*/v1/trust-profiles/${PROFILE}/issuers`, () => HttpResponse.json(relationship ? [relationship] : [])),
    http.patch(`*/v1/issuer-entities/${ISSUER}`, async ({ request }) => {
      const body = await record(request);
      if (body.organization_id !== ORG) return HttpResponse.json({ detail: 'organization_id is required and must match' }, { status: 422 });
      issuer = { ...issuer, ...body, updated_at: '2026-11-26T12:00:01Z' };
      return HttpResponse.json(nativeResponse(issuer));
    }),
    http.post('*/v1/issuer-entities', async ({ request }) => {
      issuer = { ...await record(request), id: ISSUER, updated_at: NOW };
      return HttpResponse.json(nativeResponse(issuer));
    }),
    http.patch(`*/v1/trust-profiles/${PROFILE}/issuers/${ISSUER}`, async ({ request }) => {
      relationship = { ...relationship, ...await record(request), updated_at: '2026-11-26T12:00:01Z' };
      return HttpResponse.json(nativeResponse(relationship));
    }),
    http.post(`*/v1/trust-profiles/${PROFILE}/issuers`, async ({ request }) => {
      relationship = { ...await record(request), id: 'relationship-wallet', trust_profile_id: PROFILE, updated_at: NOW };
      return HttpResponse.json(nativeResponse(relationship));
    }),
    http.patch(`*/v1/trust-profiles/${PROFILE}`, async ({ request }) => {
      profile = { ...profile, ...await record(request), updated_at: '2026-11-26T12:00:02Z' };
      return HttpResponse.json(profile);
    }),
  );
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Wallet trust owner API boundary', () => {
  it('retains both managed and registered verifier identities, disabled state and public registrations', async () => {
    const source = { id: 'managed-source', source_type: 'MANAGED_FLOW_VERIFIER', purposes: ['PRESENTATION_VERIFIER'], enabled: false,
      managed_flow_verifier: { producer_id: 'flow-primary', public_base_url: 'https://api.example.test', verifier_did: DID,
        request_key_id: JWK.kid, public_jwk: JWK, valid_from: NOW, valid_until: '2027-11-26T12:00:00Z' } };
    const registered = { id: 'registered-source', source_type: 'REGISTERED_VERIFIER', purposes: ['PRESENTATION_VERIFIER'], enabled: true,
      registered_verifier: { client_id: 'registered-client', request_key_id: JWK.kid, public_jwk: JWK,
        response_uris: ['https://verifier.example.test/callback'], valid_from: NOW, valid_until: '2027-11-26T12:00:00Z' } };
    await updateTrustProfile(PROFILE, { trust_sources: [source, registered] });
    expect(writes[0].body).toEqual({ trust_sources: [source, registered] });
  });

  it('uses the human-session transport and preserves unrelated issuer and relationship metadata', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const result = await saveWalletIssuerTrust(PROFILE, ORG, input());
    expect(writes.map((write) => write.path)).toEqual([
      `/v1/issuer-entities/${ISSUER}`, `/v1/trust-profiles/${PROFILE}/issuers/${ISSUER}`, `/v1/trust-profiles/${PROFILE}`,
    ]);
    expect(writes[0].body.metadata).toEqual({ retained_annotation: { source: 'owner' }, verification_keys: [JWK] });
    expect(writes[0].body.organization_id).toBe(ORG);
    expect(writes[1].body).toEqual({ metadata: { retained_annotation: ['keep', null],
      marty_credential_authorizations_v1: grants, marty_wallet_issuance_authorizations_v1: issuance } });
    expect(result.relationship.trust_level).toBe(70);
    expect(result.relationship.metadata.marty_wallet_issuance_authorizations_v1).toEqual(nativeResponse(issuance));
    expect(result.relationship.metadata.retained_annotation).toEqual(['keep', null]);
    expect(result.profile.status).toBe('draft');
    expect(writes[2].body).toEqual({ compliance_status: 'COMPLIANT', allowed_issuers: ['did:web:retained.example', DID] });
    const writeOptions = fetchSpy.mock.calls.filter(([, options]) => options?.method === 'PATCH').map(([, options]) => options?.credentials);
    fetchSpy.mockRestore();
    expect(writeOptions).toEqual(['include', 'include', 'include']);
    for (const write of writes) {
      for (const name of ['authorization', 'x-user-id', 'x-service-token', 'x-api-key']) expect(write.headers.has(name)).toBe(false);
    }
  });

  it('refuses private key material before dispatching any write', async () => {
    await expect(saveWalletIssuerTrust(PROFILE, ORG, { ...input(), verification_keys: [{ ...JWK, d: 'never-transmit-this' }] }))
      .rejects.toThrow(/public signing keys only/i);
    expect(writes).toEqual([]);
  });

  it('rejects an off-curve public key before making any owner write', async () => {
    await expect(saveWalletIssuerTrust(PROFILE, ORG, {
      ...input(), verification_keys: [{ ...JWK, x: 'A'.repeat(43), y: 'A'.repeat(43) }],
    })).rejects.toThrow(/public signing key is invalid/i);
    expect(writes).toEqual([]);
  });

  it('rejects mismatched verifier registration fields before their material can be dispatched', async () => {
    for (const other of [{ public_jwk: { ...JWK, d: 'private-material' } }, null]) {
      await expect(updateTrustProfile(PROFILE, { trust_sources: [{ source_type: 'REGISTERED_VERIFIER',
        registered_verifier: { request_key_id: JWK.kid, public_jwk: JWK }, managed_flow_verifier: other }] }))
        .rejects.toThrow(/registration matching the verifier source type/i);
      await expect(updateTrustProfile(PROFILE, { trust_sources: [{ source_type: 'MANAGED_FLOW_VERIFIER',
        registered_verifier: other, managed_flow_verifier: { request_key_id: JWK.kid, public_jwk: JWK } }] }))
        .rejects.toThrow(/registration matching the verifier source type/i);
    }
    expect(writes).toEqual([]);
  });

  it('refuses to review a profile when the owner response omits saved public keys', async () => {
    server.use(http.patch(`*/v1/issuer-entities/${ISSUER}`, async ({ request }) => {
      const body = await record(request);
      return HttpResponse.json({ ...issuer, ...body, metadata: { retained_annotation: { source: 'owner' } } });
    }));
    await expect(saveWalletIssuerTrust(PROFILE, ORG, input())).rejects.toMatchObject({ walletReloadRequired: true });
    expect(writes.map((write) => write.path)).toEqual([`/v1/issuer-entities/${ISSUER}`]);
    expect(profile.compliance_status).toBe('SETUP_REQUIRED');
  });

  it.each(['marty_credential_authorizations_v1', 'marty_wallet_issuance_authorizations_v1'])(
    'refuses to mark the profile reviewed when the saved %s response is stale', async (field) => {
      server.use(http.patch(`*/v1/trust-profiles/${PROFILE}/issuers/${ISSUER}`, async ({ request }) => {
        const body = await record(request);
        return HttpResponse.json(nativeResponse({ ...relationship, ...body, metadata: { ...body.metadata, [field]: [] } }));
      }));
      await expect(saveWalletIssuerTrust(PROFILE, ORG, input())).rejects.toMatchObject({ walletReloadRequired: true });
      expect(writes.map((write) => write.path)).toEqual([`/v1/issuer-entities/${ISSUER}`, `/v1/trust-profiles/${PROFILE}/issuers/${ISSUER}`]);
      expect(profile.compliance_status).toBe('SETUP_REQUIRED');
    },
  );

  it('refuses a changed profile or an issuer returned from another organization', async () => {
    const original = input();
    profile.updated_at = '2026-11-26T12:00:03Z';
    await expect(saveWalletIssuerTrust(PROFILE, ORG, original)).rejects.toThrow(/profile changed/i);
    profile.updated_at = NOW;
    issuer.organization_id = 'another-organization';
    await expect(saveWalletIssuerTrust(PROFILE, ORG, original)).rejects.toThrow(/organization scope/i);
    expect(writes).toEqual([]);
  });

  it('never follows an obsolete issuer write with a relationship or profile mutation', async () => {
    let current = true;
    server.use(http.patch(`*/v1/issuer-entities/${ISSUER}`, async ({ request }) => {
      await record(request); current = false; return HttpResponse.json(issuer);
    }));
    await expect(saveWalletIssuerTrust(PROFILE, ORG, input(), { isCurrent: () => current })).rejects.toMatchObject({ name: 'AbortError' });
    expect(writes.map((write) => write.path)).toEqual([`/v1/issuer-entities/${ISSUER}`]);
  });

  it('reports a partially saved issuer without replaying a failed relationship or marking the profile reviewed', async () => {
    const request = input(false); issuer = null; relationship = null;
    server.use(http.post(`*/v1/trust-profiles/${PROFILE}/issuers`, async ({ request }) => {
      await record(request); return HttpResponse.json({ detail: 'Relationship save unavailable' }, { status: 503 });
    }));
    await expect(saveWalletIssuerTrust(PROFILE, ORG, request)).rejects.toMatchObject({ walletReloadRequired: true });
    expect(writes.map((write) => write.path)).toEqual(['/v1/issuer-entities', `/v1/trust-profiles/${PROFILE}/issuers`]);
    expect(profile.compliance_status).toBe('SETUP_REQUIRED');
  });

  it('stops before linking when an issuer update response changes its server identity', async () => {
    server.use(http.patch(`*/v1/issuer-entities/${ISSUER}`, async ({ request }) => {
      await record(request); return HttpResponse.json({ ...issuer, id: 'unexpected-issuer' });
    }));
    await expect(saveWalletIssuerTrust(PROFILE, ORG, input())).rejects.toMatchObject({ walletReloadRequired: true });
    expect(writes).toHaveLength(1);
  });
});
