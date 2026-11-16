import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { fireEvent, renderWithRouter, screen, waitFor } from '@test/utils';
import TrustProfileEditPage from '../TrustProfileEditPage';

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ isLoading: false, can: () => true }),
}));

const nativeFormats = [
  ['VC_JWT', 'jwt_vc'],
  ['SD_JWT_VC', 'sd_jwt_vc'],
  ['MDOC', 'mdoc'],
  ['JSON_LD', 'ldp_vc'],
  ['VDS_NC', 'vds_nc'],
];
let profile: Record<string, unknown>;
let patches: Array<Record<string, unknown>>;

function renderPage() {
  return renderWithRouter(<Routes>
    <Route path="/console/org/trust/profiles/:id/edit" element={<TrustProfileEditPage />} />
    <Route path="/console/org/trust/profiles/:id" element={<h1>Profile details</h1>} />
  </Routes>, { initialEntries: ['/console/org/trust/profiles/profile-1/edit'] });
}

beforeEach(() => {
  window.history.replaceState({}, '', '/');
  patches = [];
  profile = {
    id: 'profile-1', organization_id: 'org-1', name: 'Native trust profile',
    description: 'Stored configuration', profile_type: 'CUSTOM', status: 'ACTIVE',
    supported_formats: ['SD_JWT_VC'], trust_sources: [],
  };
  server.use(
    http.get('*/v1/trust-profiles/profile-1', () => HttpResponse.json(profile)),
    http.patch('*/v1/trust-profiles/profile-1', async ({ request }) => {
      const patch = await request.json() as Record<string, unknown>;
      patches.push(patch);
      profile = { ...profile, ...patch };
      return HttpResponse.json(profile);
    }),
  );
});

describe('Trust Profile editor native format readback', () => {
  it.each(nativeFormats)('shows only the stored %s selection through the real API adapter', async (native, checkbox) => {
    profile.supported_formats = [native];
    renderPage();
    await screen.findByDisplayValue('Native trust profile');
    expect(screen.getByTestId(`edit.trustProfile.format.${checkbox}`)).toBeChecked();
    expect(screen.getAllByRole('checkbox').filter((element) => (element as HTMLInputElement).checked)).toHaveLength(1);
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    expect(await screen.findByRole('heading', { name: 'Profile details' })).toBeInTheDocument();
    expect(patches).toEqual([]);
  });

  it('keeps a native subset for a managed framework instead of displaying its creation preset', async () => {
    profile.profile_type = 'EUDI';
    profile.supported_formats = ['SD_JWT_VC'];
    renderPage();
    await screen.findByDisplayValue('Native trust profile');
    expect(screen.getByTestId('edit.trustProfile.format.sd_jwt_vc')).toBeChecked();
    expect(screen.getByTestId('edit.trustProfile.format.mdoc')).not.toBeChecked();
    expect(screen.getByTestId('edit.trustProfile.format.sd_jwt_vc')).toBeDisabled();
    fireEvent.change(screen.getByTestId('edit.trustProfile.name'), { target: { value: 'Renamed profile' } });
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    await waitFor(() => expect(patches).toEqual([{ name: 'Renamed profile' }]));
  });

  it('retains native VDS_NC when another format is deliberately added', async () => {
    profile.supported_formats = ['SD_JWT_VC', 'VDS_NC'];
    renderPage();
    await screen.findByDisplayValue('Native trust profile');
    expect(screen.getByTestId('edit.trustProfile.format.vds_nc')).toBeChecked();
    fireEvent.click(screen.getByTestId('edit.trustProfile.format.ldp_vc'));
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    await waitFor(() => expect(patches).toEqual([{ supported_formats: ['SD_JWT_VC', 'VDS_NC', 'JSON_LD'] }]));
  });

  it('does not reintroduce default formats after the final selected box is cleared', async () => {
    profile.supported_formats = ['sd_jwt_vc'];
    renderPage();
    await screen.findByDisplayValue('Native trust profile');
    fireEvent.click(screen.getByTestId('edit.trustProfile.format.sd_jwt_vc'));
    expect(screen.getAllByRole('checkbox').every((element) => !(element as HTMLInputElement).checked)).toBe(true);
    fireEvent.click(screen.getByTestId('edit.trustProfile.format.ldp_vc'));
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    await waitFor(() => expect(patches).toEqual([{ supported_formats: ['JSON_LD'] }]));
  });

  it.each([null, [], undefined].map((formats) => ({ formats })))('does not invent credential formats for a machine-purpose profile with $formats', async ({ formats }) => {
    profile.trust_purposes = ['MACHINE_IDENTITY_CA'];
    profile.trusted_assertion_formats = ['X509_CERTIFICATE'];
    profile.supported_formats = formats;
    renderPage();
    await screen.findByDisplayValue('Native trust profile');
    expect(screen.getAllByRole('checkbox').every((element) => !(element as HTMLInputElement).checked)).toBe(true);
    fireEvent.change(screen.getByTestId('edit.trustProfile.description'), { target: { value: '' } });
    fireEvent.click(screen.getByTestId('edit.trustProfile.save'));
    await waitFor(() => expect(patches).toEqual([{ description: '' }]));
  });

  it.each(['SD_JWT_VC', ['FUTURE_FORMAT'], ['SD_JWT_VC', 'FUTURE_FORMAT'], ['SD_JWT_VC', null], ['MDOC', 'MDOC']].map((formats) => ({ formats })))(
    'rejects an unsupported or malformed stored format set $formats without showing defaults', async ({ formats }) => {
      profile.supported_formats = formats;
      renderPage();
      expect(await screen.findByRole('alert')).toHaveTextContent(/invalid|incomplete/i);
      expect(screen.queryByTestId('edit.trustProfile.name')).not.toBeInTheDocument();
      expect(patches).toEqual([]);
    },
  );
});
