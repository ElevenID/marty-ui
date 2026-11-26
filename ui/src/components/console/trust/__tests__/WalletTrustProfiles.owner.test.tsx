import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { fireEvent, renderWithRouter, screen, waitFor } from '@test/utils';
import TrustProfileWizard from '../TrustProfileWizard';
import TrustProfileEditPage from '../TrustProfileEditPage';

const { context, grants, auth } = vi.hoisted(() => ({
  context: { activeOrgId: 'org-wallet' }, grants: new Set<string>(),
  auth: { isAuthenticated: true, user: { id: 'owner-wallet' } },
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../../../hooks/usePermissions', () => ({ usePermissions: () => ({ isLoading: false,
  can: (resource: string, action: string) => grants.has(`${resource}:${action}`) }) }));
vi.mock('../../../../services/walletRegistryApi', () => ({ listWallets: async () => [] }));

const ORG = 'org-wallet';
const ID = 'profile-wallet';
const DID = 'did:web:verifier.example.test:wallet';
const JWK = { ...generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }), kid: `${DID}#key-1`, use: 'sig', alg: 'ES256' };
const NOW = '2026-11-26T12:00:00Z';
const EDIT = `/console/org/trust/profiles/${ID}/edit`;
let profile: any;
let writes: Array<{ path: string; body: any }>;
const source = () => ({ id: 'source-wallet', source_type: 'MANAGED_FLOW_VERIFIER', enabled: true, purposes: ['PRESENTATION_VERIFIER'],
  description: 'Owner-approved verifier purpose; retain this description.',
  managed_flow_verifier: { producer_id: 'flow-primary', public_base_url: 'https://api.example.test', verifier_did: DID,
    request_key_id: JWK.kid, public_jwk: JWK, valid_from: NOW, valid_until: '2027-11-26T12:00:00Z' } });

function routes() {
  return <Routes>
    <Route path="/console/org/trust/profiles/new" element={<TrustProfileWizard />} />
    <Route path="/console/org/trust/profiles/:id/edit" element={<TrustProfileEditPage />} />
    <Route path="/console/org/trust/profiles/:id" element={<h1>Profile details</h1>} />
  </Routes>;
}
function edit() { return renderWithRouter(routes(), { initialEntries: [EDIT] }); }
async function record(request: Request) {
  const body = await request.json(); writes.push({ path: new URL(request.url).pathname, body }); return body;
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  window.history.replaceState({}, '', '/');
  context.activeOrgId = ORG; auth.isAuthenticated = true; auth.user = { id: 'owner-wallet' };
  grants.clear();
  for (const resource of ['trust-profile', 'trusted-issuer']) {
    for (const action of ['view', 'create', 'edit', 'activate']) grants.add(`${resource}:${action}`);
  }
  writes = [];
  profile = { id: ID, organization_id: ORG, name: 'Wallet trust', description: '', profile_type: 'CUSTOM',
    status: 'draft', compliance_status: 'SETUP_REQUIRED', updated_at: NOW,
    trust_purposes: ['PRESENTATION_VERIFIER'], trust_sources: [source()], supported_formats: [],
    allowed_issuers: [], revocation_policy: { check_mode: 'HARD_FAIL', cache_ttl_seconds: 3600 },
    revocation_services: { enabled_methods: [], auto_discover: false, merge_discovered: false },
    time_policy: { clock_skew_seconds: 30, require_freshness: false } };
  server.use(
    http.get(`*/v1/trust-profiles/${ID}`, () => HttpResponse.json(profile)),
    http.patch(`*/v1/trust-profiles/${ID}`, async ({ request }) => {
      const body = await record(request);
      profile = { ...profile, ...body, updated_at: '2026-11-26T12:00:01Z' };
      // Native JSON maps do not preserve the order of an imported JWK's keys.
      if (profile.trust_sources) profile.trust_sources = profile.trust_sources.map((item: any) => item.managed_flow_verifier ? {
        ...item, managed_flow_verifier: { ...item.managed_flow_verifier,
          public_jwk: Object.fromEntries(Object.entries(item.managed_flow_verifier.public_jwk).sort(([a], [b]) => a.localeCompare(b))) },
      } : item);
      return HttpResponse.json(profile);
    }),
    http.post(`*/v1/trust-profiles/${ID}/activate`, async ({ request }) => {
      await record(request); profile = { ...profile, status: 'active', updated_at: '2026-11-26T12:00:02Z' }; return HttpResponse.json(profile);
    }),
  );
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Managed wallet Trust Profile owner forms', () => {
  it('creates an explicitly chosen verifier draft and opens configuration without activation', async () => {
    server.use(http.post('*/v1/trust-profiles', async ({ request }) => {
      profile = { ...profile, ...await record(request), id: ID, status: 'draft' };
      return HttpResponse.json(profile);
    }));
    const { user } = renderWithRouter(routes(), { initialEntries: ['/console/org/trust/profiles/new'] });
    await user.click(screen.getByRole('combobox', { name: 'Trust configuration' }));
    await user.click(screen.getByRole('option', { name: 'Paired wallet verifiers' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Profile name' }), { target: { value: 'Staging wallet verifier' } });
    await user.click(screen.getByRole('checkbox', { name: 'Use this dedicated wallet trust policy' }));
    await user.click(screen.getByRole('button', { name: 'Create draft and configure' }));
    expect(await screen.findByRole('heading', { name: 'Wallet verifier configuration' })).toBeInTheDocument();
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ path: '/v1/trust-profiles', body: {
      organization_id: ORG, profile_type: 'CUSTOM', trust_purposes: ['PRESENTATION_VERIFIER'],
      compliance_status: 'SETUP_REQUIRED', supported_formats: [], trust_sources: [],
    } });
    expect(writes[0].body.status).toBeUndefined();
  });

  it('saves an explicitly reviewed disabled verifier while retaining another source and existing source IDs', async () => {
    const retained = { id: 'source-other', source_type: 'REGISTERED_VERIFIER', enabled: false, purposes: ['PRESENTATION_VERIFIER'],
      registered_verifier: { client_id: 'other-client', request_key_id: JWK.kid, public_jwk: JWK,
        response_uris: ['https://other.example.test/callback'], valid_from: NOW, valid_until: '2027-11-26T12:00:00Z' } };
    profile.trust_sources.push(retained);
    edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    const save = screen.getByRole('button', { name: 'Save verifier configuration' });
    expect(save).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable this verifier when the profile is active' }));
    fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed this verifier/ }));
    fireEvent.click(save);
    expect(await screen.findByText('Verifier configuration saved. Profile activation is a separate action.')).toBeInTheDocument();
    expect(writes).toHaveLength(1);
    expect(writes[0].body).toEqual({ compliance_status: 'COMPLIANT', trust_sources: [{ ...source(), enabled: false }, retained] });
    expect(profile.status).toBe('draft');
  });

  it('does not send a private key entered into the public verifier key field', async () => {
    edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Public request signing key (JWK)' }), {
      target: { value: JSON.stringify({ ...JWK, d: 'private-material-must-stay-local' }) },
    });
    fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed this verifier/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save verifier configuration' }));
    expect(await screen.findByText(/Import public signing keys only/)).toBeInTheDocument();
    expect(writes).toEqual([]);
  });

  it('stops before a verifier write when edit permission is lost during the fresh read', async () => {
    let calls = 0;
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    server.use(http.get(`*/v1/trust-profiles/${ID}`, async () => {
      calls += 1; if (calls === 2) await pending; return HttpResponse.json(profile);
    }));
    const view = edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed this verifier/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save verifier configuration' }));
    await waitFor(() => expect(calls).toBe(2));
    grants.delete('trust-profile:edit');
    view.rerender(routes());
    await screen.findByText(/do not have permission/i);
    release();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Save verifier configuration' })).not.toBeInTheDocument());
    expect(writes).toEqual([]);
  });

  it('keeps basic profile edits and wallet saves mutually exclusive while a real owner write is pending', async () => {
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    server.use(http.patch(`*/v1/trust-profiles/${ID}`, async ({ request }) => {
      const body = await record(request); await pending;
      profile = { ...profile, ...body, updated_at: '2026-11-26T12:00:01Z' };
      return HttpResponse.json(profile);
    }));
    edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    const name = screen.getByTestId('edit.trustProfile.name');
    fireEvent.change(name, { target: { value: 'Unsaved basic name' } });
    expect(screen.getByRole('button', { name: 'Save verifier configuration' })).toBeDisabled();
    expect(screen.getByText(/Save or discard the basic profile changes/)).toBeInTheDocument();
    fireEvent.change(name, { target: { value: 'Wallet trust' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed this verifier/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save verifier configuration' }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(name).toBeDisabled();
    expect(screen.getByRole('combobox', { name: 'Verifier registration' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByTestId('edit.trustProfile.save')).toBeDisabled();
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    expect(writes).toHaveLength(1);
    release();
    await screen.findByText('Verifier configuration saved. Profile activation is a separate action.');
    expect(name).toBeEnabled();
  });

  it('activates only after explicit confirmation and updates the profile status shown beside the owner form', async () => {
    profile.compliance_status = 'COMPLIANT';
    edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    expect(writes).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: 'Activate reviewed profile' }));
    await screen.findByRole('dialog', { name: 'Activate wallet trust profile' });
    expect(writes).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm activation' }));
    expect(await screen.findByText('This wallet trust profile is active.')).toBeInTheDocument();
    expect(writes).toEqual([{ path: `/v1/trust-profiles/${ID}/activate`, body: {} }]);
    expect(screen.getByTestId('edit.trustProfile.status')).toHaveValue('active');
    expect(screen.queryByRole('button', { name: 'Activate reviewed profile' })).not.toBeInTheDocument();
  });

  it('requires a reload instead of activating a profile whose saved configuration changed', async () => {
    profile.compliance_status = 'COMPLIANT';
    edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    fireEvent.click(screen.getByRole('button', { name: 'Activate reviewed profile' }));
    profile = { ...profile, updated_at: '2026-11-26T12:00:03Z' };
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm activation' }));
    expect(await screen.findByText('The saved profile changed. Reload and review it before activation.')).toBeInTheDocument();
    expect(writes).toEqual([]);
    expect(screen.getByRole('button', { name: 'Confirm activation' })).toBeDisabled();
  });

  it('never activates after permission is lost while the current saved profile is being read', async () => {
    profile.compliance_status = 'COMPLIANT';
    let calls = 0;
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    server.use(http.get(`*/v1/trust-profiles/${ID}`, async () => {
      calls += 1; if (calls === 2) await pending; return HttpResponse.json(profile);
    }));
    const view = edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    fireEvent.click(screen.getByRole('button', { name: 'Activate reviewed profile' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm activation' }));
    await waitFor(() => expect(calls).toBe(2));
    grants.delete('trust-profile:activate');
    view.rerender(routes());
    await screen.findByText('An owner with profile activation permission must activate this profile.');
    release();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(writes).toEqual([]);
    expect(screen.getByRole('button', { name: 'Activate reviewed profile' })).toBeDisabled();
  });

  it('does not replay an uncertain activation and recovers the actual active state through an explicit reload', async () => {
    profile.compliance_status = 'COMPLIANT';
    server.use(http.post(`*/v1/trust-profiles/${ID}/activate`, async ({ request }) => {
      await record(request); profile = { ...profile, status: 'active', updated_at: '2026-11-26T12:00:02Z' };
      return HttpResponse.json({ detail: 'Activation response unavailable' }, { status: 503 });
    }));
    edit();
    await screen.findByRole('heading', { name: 'Wallet verifier configuration' });
    fireEvent.click(screen.getByRole('button', { name: 'Activate reviewed profile' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm activation' }));
    await screen.findByText(/Activation response unavailable/);
    expect(writes).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Confirm activation' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel', exact: true, hidden: false }));
    fireEvent.click(await screen.findByRole('button', { name: 'Reload wallet configuration' }));
    expect(await screen.findByText('This wallet trust profile is active.')).toBeInTheDocument();
    expect(screen.getByTestId('edit.trustProfile.status')).toHaveValue('active');
    expect(writes).toHaveLength(1);
  });

  it('creates a real owner issuer and exact grants through the issuer form, without activating the profile', async () => {
    profile = { ...profile, trust_purposes: ['CREDENTIAL_ISSUER'], supported_formats: ['SD_JWT_VC'], trust_sources: [] };
    let issuer: any = null;
    let relationship: any = null;
    server.use(
      http.get('*/v1/issuer-entities', () => HttpResponse.json(issuer ? [issuer] : [])),
      http.get(`*/v1/trust-profiles/${ID}/issuers`, () => HttpResponse.json(relationship ? [relationship] : [])),
      http.post('*/v1/issuer-entities', async ({ request }) => {
        issuer = { ...await record(request), id: 'owned-issuer', updated_at: NOW }; return HttpResponse.json(issuer);
      }),
      http.post(`*/v1/trust-profiles/${ID}/issuers`, async ({ request }) => {
        relationship = { ...await record(request), id: 'owned-relationship', trust_profile_id: ID, updated_at: NOW };
        return HttpResponse.json(relationship);
      }),
    );
    edit();
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Issuer display name' })).toBeEnabled());
    fireEvent.change(screen.getByRole('textbox', { name: 'Issuer display name' }), { target: { value: 'Owner-approved demo issuer' } });
    fireEvent.change(screen.getByRole('textbox', { name: 'Credential issuer identifier' }), { target: { value: DID } });
    fireEvent.change(screen.getByRole('textbox', { name: 'Public issuer signing keys (JWK array)' }), { target: { value: JSON.stringify([JWK]) } });
    fireEvent.change(screen.getByRole('textbox', { name: 'Accepted credential types' }), { target: { value: 'https://types.example.test/WalletDemo' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed this issuer/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Save issuer configuration' }));
    expect(await screen.findByText('Issuer keys and grants saved. Profile activation is a separate action.')).toBeInTheDocument();
    expect(writes.map((write) => write.path)).toEqual(['/v1/issuer-entities', `/v1/trust-profiles/${ID}/issuers`, `/v1/trust-profiles/${ID}`]);
    expect(writes[0].body).toMatchObject({ organization_id: ORG, issuer_id: DID, metadata: { verification_keys: [JWK] } });
    expect(writes[1].body.metadata).toEqual({ marty_credential_authorizations_v1: [{ format: 'SD_JWT_VC', vct: 'https://types.example.test/WalletDemo' }], marty_wallet_issuance_authorizations_v1: [] });
    expect(profile.status).toBe('draft');
  });
});
