import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import catalog from '../../../../contracts/protocol-support-catalog.json';
import { getProtocolSupportCatalog, normalizeProtocolSupportCatalog } from '../protocolSupportApi';

describe('protocol support catalog client', () => {
  it('loads the gateway-owned public catalog and preserves explicit support states', async () => {
    let requested = '';
    server.use(http.get('http://localhost:8000/v1/protocol-support', ({ request }) => {
      requested = new URL(request.url).pathname;
      return HttpResponse.json(catalog);
    }));
    const result = await getProtocolSupportCatalog();
    expect(requested).toBe('/v1/protocol-support');
    expect(result.protocol_revision).toBe('76c37dc229b328afe002b911a26624543f814a64');
    expect(result.entities.find((entry) => entry.id === 'wallet-profile')?.support_level).toBe('derived');
    expect(result.entities.filter((entry) => entry.support_level === 'unsupported').map((entry) => entry.id)).toEqual([
      'machine-identity',
      'machine-authentication-policy',
      'authorization-decision-receipt',
    ]);
  });

  it('rejects unsupported entries that advertise routes or schemas', () => {
    const invalid = structuredClone(catalog);
    const machine = invalid.entities.find((entry) => entry.id === 'machine-identity');
    machine.api_paths = ['/v1/machine-identities'];
    expect(() => normalizeProtocolSupportCatalog(invalid)).toThrow(
      'Unsupported protocol entity machine-identity cannot advertise product surfaces.',
    );
  });

  it('rejects duplicate identities and unknown support labels', () => {
    const duplicate = structuredClone(catalog);
    duplicate.entities.push(structuredClone(duplicate.entities[0]));
    expect(() => normalizeProtocolSupportCatalog(duplicate)).toThrow('entity IDs must be present and unique');
    const unknown = structuredClone(catalog);
    unknown.entities[0].support_level = 'available';
    expect(() => normalizeProtocolSupportCatalog(unknown)).toThrow('level is invalid');
    const unknownQualification = structuredClone(catalog);
    unknownQualification.entities[0].qualification = 'production_ready';
    expect(() => normalizeProtocolSupportCatalog(unknownQualification)).toThrow('qualification is invalid');
  });
});
