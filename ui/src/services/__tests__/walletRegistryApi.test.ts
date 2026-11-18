import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { getTemplateWalletCompatibility } from '../walletRegistryApi';
import example from '../../../../contracts/wallet-compatibility-example.json';

describe('template wallet compatibility client', () => {
  it('uses the owning public template route and preserves native derivation metadata', async () => {
    let requested = '';
    server.use(http.get('http://localhost:8000/v1/credential-templates/:id/wallet-compatibility', ({ request }) => {
      requested = new URL(request.url).pathname;
      return HttpResponse.json(example);
    }));
    expect(await getTemplateWalletCompatibility('template/with space')).toEqual(example);
    expect(requested).toBe('/v1/credential-templates/template%2Fwith%20space/wallet-compatibility');
  });

  it('rejects a missing owning template before sending a request', async () => {
    let requested = false;
    server.use(http.get('http://localhost:8000/v1/credential-templates/*', () => { requested = true; return HttpResponse.json(example); }));
    await expect(getTemplateWalletCompatibility(' ')).rejects.toThrow('A credential template ID is required.');
    expect(requested).toBe(false);
  });
});
