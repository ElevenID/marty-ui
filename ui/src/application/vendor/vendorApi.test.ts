import { describe, expect, it, vi } from 'vitest';
import {
  fetchCredentialConfigs,
  fetchCredentialTypeDefaults,
  saveCredentialConfig,
  deleteCredentialConfig,
  toggleCredentialConfigActive,
  publishCredentialType,
  previewCredentialType,
  fetchCredentialTypeVersions,
  unpublishCredentialType,
  fetchOffers,
  regenerateOffer,
  fetchAnalyticsSummary,
  fetchAnalyticsScans,
  fetchIssuedCredentials,
  revokeCredential,
  fetchRevocationHistory,
  fetchMDocConfig,
  saveMDocConfig,
  fetchIssuanceTemplates,
  fetchTrustProfiles,
  saveIssuanceTemplate,
  deleteIssuanceTemplate,
  fetchAuditEvents,
  fetchPreviewFlow,
  fetchPreviewCredentialTemplate,
  generateWalletPairingQR,
  fetchWalletPairingStatus,
} from './vendorApi';

// Mock the api service
vi.mock('../../services/api', () => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
}));

import { get, post, put, del } from '../../services/api';

describe('vendorApi', () => {
  beforeEach(() => vi.clearAllMocks());

  // ── Credential Configuration ─────────────────────────────────

  it('fetchCredentialConfigs calls GET', async () => {
    get.mockResolvedValue({ credential_types: [] });
    const data = await fetchCredentialConfigs({ organizationId: 'org-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/api/organizations/org-1/credential-types'));
    expect(data.credential_types).toEqual([]);
  });

  it('fetchCredentialTypeDefaults calls GET for a type', async () => {
    get.mockResolvedValue({ required_fields: ['name'], optional_fields: ['addr'] });
    await fetchCredentialTypeDefaults({ credentialType: 'passport' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/defaults/passport'));
  });

  it('saveCredentialConfig creates via POST', async () => {
    post.mockResolvedValue({});
    await saveCredentialConfig({ organizationId: 'org-1', id: null, body: { credential_type: 'visa' } });
    expect(post).toHaveBeenCalled();
  });

  it('saveCredentialConfig updates via PUT', async () => {
    put.mockResolvedValue({});
    await saveCredentialConfig({ organizationId: 'org-1', id: 'cfg-1', body: { is_active: true } });
    expect(put).toHaveBeenCalledWith(expect.stringContaining('/cfg-1'), { is_active: true });
  });

  it('deleteCredentialConfig calls DEL', async () => {
    del.mockResolvedValue({});
    await deleteCredentialConfig({ organizationId: 'org-1', id: 'cfg-1' });
    expect(del).toHaveBeenCalledWith(expect.stringContaining('/cfg-1'));
  });

  it('toggleCredentialConfigActive sends PUT', async () => {
    put.mockResolvedValue({});
    await toggleCredentialConfigActive({ organizationId: 'org-1', id: 'cfg-1', isActive: false });
    expect(put).toHaveBeenCalledWith(expect.stringContaining('/cfg-1'), { is_active: false });
  });

  // ── Template Actions ─────────────────────────────────────────

  it('publishCredentialType calls POST', async () => {
    post.mockResolvedValue({ credential_type: {} });
    await publishCredentialType({ orgId: 'o', typeId: 't', visibility: 'public', changeDescription: 'v1' });
    expect(post).toHaveBeenCalledWith(
      expect.stringContaining('/publish?visibility=public'),
      { change_description: 'v1' },
    );
  });

  it('previewCredentialType calls POST with test data', async () => {
    post.mockResolvedValue({ valid: true });
    await previewCredentialType({ orgId: 'o', typeId: 't', testData: { name: 'Jane' } });
    expect(post).toHaveBeenCalledWith(expect.stringContaining('/preview'), { name: 'Jane' });
  });

  it('fetchCredentialTypeVersions calls GET', async () => {
    get.mockResolvedValue({ versions: [] });
    await fetchCredentialTypeVersions({ orgId: 'o', typeId: 't' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/versions'));
  });

  it('unpublishCredentialType calls POST', async () => {
    post.mockResolvedValue({ credential_type: {} });
    await unpublishCredentialType({ orgId: 'o', typeId: 't' });
    expect(post).toHaveBeenCalledWith(expect.stringContaining('/unpublish'));
  });

  // ── Offers ───────────────────────────────────────────────────

  it('fetchOffers builds query params', async () => {
    get.mockResolvedValue({ offers: [], total: 0 });
    await fetchOffers({ organizationId: 'org-1', page: 2, pageSize: 10, statusFilter: 'active', activeFilter: '' });
    expect(get).toHaveBeenCalledWith(expect.stringMatching(/offers\?.*organization_id=org-1.*page=2/));
  });

  it('regenerateOffer calls POST', async () => {
    post.mockResolvedValue({});
    await regenerateOffer({ offerId: 'off-1' });
    expect(post).toHaveBeenCalledWith(expect.stringContaining('/off-1/regenerate'), { force: false });
  });

  // ── Analytics ────────────────────────────────────────────────

  it('fetchAnalyticsSummary defaults to 30 days', async () => {
    get.mockResolvedValue({});
    await fetchAnalyticsSummary({ organizationId: 'org-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('days=30'));
  });

  it('fetchAnalyticsScans builds filter params', async () => {
    get.mockResolvedValue({ scans: [], total: 0 });
    await fetchAnalyticsScans({ organizationId: 'org-1', page: 1, pageSize: 25, accessTypeFilter: 'qr', outcomeFilter: '', walletTypeFilter: '' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('access_type=qr'));
  });

  // ── Revocation ───────────────────────────────────────────────

  it('fetchIssuedCredentials builds query with search', async () => {
    get.mockResolvedValue({ credentials: [], total: 0 });
    await fetchIssuedCredentials({ organizationId: 'org-1', page: 1, perPage: 10, searchQuery: 'jane' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('search=jane'));
  });

  it('revokeCredential calls POST', async () => {
    post.mockResolvedValue({});
    await revokeCredential({ credentialId: 'c1', reason: 'lost', comments: 'test' });
    expect(post).toHaveBeenCalledWith(expect.stringContaining('/c1/revoke'), { reason: 'lost', comments: 'test' });
  });

  it('fetchRevocationHistory builds offset params', async () => {
    get.mockResolvedValue({ revocations: [] });
    await fetchRevocationHistory({ organizationId: 'org-1', limit: 25, offset: 50 });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('offset=50'));
  });

  // ── mDoc Config ──────────────────────────────────────────────

  it('fetchMDocConfig calls GET', async () => {
    get.mockResolvedValue({ enabled_types: {} });
    await fetchMDocConfig({ organizationId: 'org-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/mdoc-config'));
  });

  it('saveMDocConfig calls PUT', async () => {
    put.mockResolvedValue({});
    await saveMDocConfig({ organizationId: 'org-1', enabledTypes: {}, typeConfigs: {} });
    expect(put).toHaveBeenCalledWith(expect.stringContaining('/mdoc-config'), { enabled_types: {}, type_configs: {} });
  });

  // ── Issuance Templates ──────────────────────────────────────

  it('fetchIssuanceTemplates calls GET', async () => {
    get.mockResolvedValue({ templates: [] });
    await fetchIssuanceTemplates({ organizationId: 'org-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('organization_id=org-1'));
  });

  it('fetchTrustProfiles calls GET', async () => {
    get.mockResolvedValue({ profiles: [] });
    await fetchTrustProfiles({ organizationId: 'org-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('trust-profiles'));
  });

  it('saveIssuanceTemplate creates via POST when no id', async () => {
    post.mockResolvedValue({});
    await saveIssuanceTemplate({ templateData: { name: 'T' }, organizationId: 'org-1' });
    expect(post).toHaveBeenCalled();
  });

  it('saveIssuanceTemplate updates via PUT when id exists', async () => {
    put.mockResolvedValue({});
    await saveIssuanceTemplate({ templateData: { id: 't-1', name: 'T' }, organizationId: 'org-1' });
    expect(put).toHaveBeenCalledWith(expect.stringContaining('/t-1'), expect.objectContaining({ name: 'T' }));
  });

  it('deleteIssuanceTemplate calls DEL', async () => {
    del.mockResolvedValue({});
    await deleteIssuanceTemplate({ templateId: 't-1' });
    expect(del).toHaveBeenCalledWith(expect.stringContaining('/t-1'));
  });

  // ── Audit Logs ───────────────────────────────────────────────

  it('fetchAuditEvents builds filter params', async () => {
    get.mockResolvedValue({ events: [], total: 0 });
    await fetchAuditEvents({
      organizationId: 'org-1', page: 1, perPage: 50, timeRange: '24h',
      categoryFilter: 'access', severityFilter: 'all', searchQuery: '',
    });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('category=access'));
  });

  // ── Preview ──────────────────────────────────────────────────

  it('fetchPreviewFlow calls GET', async () => {
    get.mockResolvedValue({ name: 'Test Flow' });
    await fetchPreviewFlow({ flowId: 'f-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/flows/f-1?preview=true'));
  });

  it('fetchPreviewCredentialTemplate calls GET', async () => {
    get.mockResolvedValue({ name: 'Visa' });
    await fetchPreviewCredentialTemplate({ templateId: 't-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/credential-templates/t-1?preview=true'));
  });

  // ── Wallet Pairing ──────────────────────────────────────────

  it('generateWalletPairingQR calls POST', async () => {
    post.mockResolvedValue({ qr_data: 'abc' });
    await generateWalletPairingQR();
    expect(post).toHaveBeenCalledWith(expect.stringContaining('/wallet/pairing/generate'));
  });

  it('fetchWalletPairingStatus calls GET', async () => {
    get.mockResolvedValue({ status: 'scanning' });
    await fetchWalletPairingStatus({ pairingToken: 'tok-1' });
    expect(get).toHaveBeenCalledWith(expect.stringContaining('/wallet/pairing/tok-1/status'));
  });
});
