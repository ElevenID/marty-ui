import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { getKeyManagementConfig, updateKeyManagementConfig } from '../signingKeysApi';
import { createKeyManagementConfigUpdate } from '../../components/console/deploy/keyManagementServiceCatalog';

const revision = '"r-e4195bec-8a3a-43d5-828d-c7b5a0c4921c"';

describe('shared KMS registration API client', () => {
  it('keeps the registry revision and all registrations when changing a default', async () => {
    const registry = {
      config_revision: revision,
      services: ['first', 'second'].map((id) => ({ id, service_type: 'aws-kms' })),
      default_service_id: 'first',
      type_defaults: { vc_jwt_issuer: 'first' },
      format_defaults: { JWT: 'first' },
      key_reference_purposes: { first: { 'key-one': ['vc_jwt_issuer'] } },
    };
    let writes = 0;
    server.use(
      http.get('*/v1/signing-keys/config', ({ request }) => {
        expect(new URL(request.url).searchParams.get('organization_id')).toBe('org-a');
        return HttpResponse.json(registry, { headers: { ETag: revision } });
      }),
      http.patch('*/v1/signing-keys/config', async ({ request }) => {
        writes += 1;
        expect(new URL(request.url).searchParams.get('organization_id')).toBe('org-a');
        expect(request.headers.get('If-Match')).toBe(revision);
        const body = await request.json() as Record<string, unknown>;
        expect(body).not.toHaveProperty('config_revision');
        expect(body).not.toHaveProperty('organization_id');
        expect(body.default_service_id).toBe('second');
        expect((body.services as { id: string }[]).map((service) => service.id)).toEqual(['first', 'second']);
        expect(body.type_defaults).toEqual(registry.type_defaults);
        expect(body.format_defaults).toEqual(registry.format_defaults);
        expect(body.key_reference_purposes).toEqual(registry.key_reference_purposes);
        return HttpResponse.json({ ...body, config_revision: revision });
      }),
    );
    const current = await getKeyManagementConfig({ organization_id: 'org-a' });
    await updateKeyManagementConfig({ organization_id: 'org-a',
      ...createKeyManagementConfigUpdate(current, { default_service_id: 'second' }) });
    expect(writes).toBe(1);
  });

  it('requires a read revision and does not retry a conflicting replacement', async () => {
    let writes = 0;
    server.use(http.patch('*/v1/signing-keys/config', () => {
      writes += 1;
      return HttpResponse.json({ detail: 'Signing registry changed since the supplied revision.' }, { status: 412 });
    }));
    for (const invalid of [undefined, '', '*', `W/${revision}`, '"not-a-revision"']) {
      await expect(updateKeyManagementConfig({ organization_id: 'org-a', services: [], config_revision: invalid }))
        .rejects.toThrow(/Reload key management configuration/);
    }
    expect(writes).toBe(0);
    await expect(updateKeyManagementConfig({ organization_id: 'org-a', services: [], config_revision: revision }))
      .rejects.toThrow();
    expect(writes).toBe(1);
  });
});
