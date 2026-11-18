import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import TrustProfilesPage from '../TrustProfilesPage';

const listTrustProfiles = vi.fn();
const listRevocationProfiles = vi.fn();
const listPublicIssuerIdentities = vi.fn();
let organizationId: string | undefined = 'org-1';

vi.mock('react-i18next', () => {
  const t = (key: string, options: Record<string, unknown> = {}) => String(options.defaultValue || ({
      'trust.trustProfiles': 'Trust Profiles',
      'trust.trustProfilesDescription': 'Manage trust profiles.',
      'trust.trustProfilesPage.title': 'Trust Profiles',
      'trust.trustProfilesPage.emptyTitle': 'No trust profiles',
      'trust.tableHeaders.name': 'Name',
      'trust.tableHeaders.framework': 'Framework',
      'trust.tableHeaders.status': 'Status',
      'trust.tableHeaders.trustedIssuers': 'Trusted Issuers',
      'trust.tableHeaders.validationRules': 'Cryptographic Policy',
      'trust.tableHeaders.lastUpdated': 'Last Updated',
      'trust.tableHeaders.actions': 'Actions',
      'trust.actions.viewDetails': 'View details',
      'trust.actions.edit': 'Edit',
    }[key] || key));
  return { useTranslation: () => ({ t }) };
});

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: organizationId }),
}));

vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ isLoading: false, can: () => true }),
}));

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listTrustProfiles: (...args: unknown[]) => listTrustProfiles(...args),
  listRevocationProfiles: (...args: unknown[]) => listRevocationProfiles(...args),
}));

vi.mock('../../../../services/issuerIdentitiesApi', () => ({
  listPublicIssuerIdentities: (...args: unknown[]) => listPublicIssuerIdentities(...args),
}));

vi.mock('../../../common', () => ({
  ResourcePage: ({ children, title }: { children: React.ReactNode; title: string }) => <div><h1>{title}</h1>{children}</div>,
  StatusChip: ({ status }: { status: string }) => <span>{status}</span>,
  EmptyState: ({ title, prerequisites }: { title?: string; prerequisites?: Array<{ label: string; status: string }> }) => (
    <div>
      <div>{title || 'empty-state'}</div>
      {prerequisites?.map((prerequisite) => <span key={prerequisite.label}>{`${prerequisite.label}:${prerequisite.status}`}</span>)}
    </div>
  ),
  EmptyStates: { trustProfiles: { title: 'No trust profiles' } },
}));

vi.mock('../../../trust', () => ({
  TrustProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe('TrustProfilesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    organizationId = 'org-1';
    listRevocationProfiles.mockResolvedValue([]);
    listPublicIssuerIdentities.mockResolvedValue({ identities: [] });
  });

  it('loads trust records without unrelated issuer or revocation APIs', async () => {
    listTrustProfiles.mockResolvedValue([{
      id: 'profile-1',
      organization_id: 'org-1',
      name: 'Production Trust',
      framework: 'custom',
      status: 'active',
      trusted_issuers: [{ id: 'issuer-1' }],
      validation_rules: { allowed_algorithms: ['ES256'] },
      updated_at: '2026-01-01T00:00:00Z',
    }]);

    renderWithRouter(<TrustProfilesPage />);
    expect(await screen.findByText('Production Trust')).toBeInTheDocument();
    expect(listTrustProfiles).toHaveBeenCalledWith({ organization_id: 'org-1', limit: 100, offset: 0 });
    expect(listPublicIssuerIdentities).not.toHaveBeenCalled();
    expect(listRevocationProfiles).not.toHaveBeenCalled();
  });

  it('shows the empty catalog without inventing setup prerequisites', async () => {
    listTrustProfiles.mockResolvedValue([]);
    listPublicIssuerIdentities.mockResolvedValue({ identities: [{ issuer_did: 'did:web:issuer.example' }] });
    renderWithRouter(<TrustProfilesPage />);

    expect(await screen.findByText('No trust profiles')).toBeInTheDocument();
    expect(screen.queryByText('Issuer Identity:ready')).not.toBeInTheDocument();
    expect(screen.queryByText('Revocation Profile:missing')).not.toBeInTheDocument();
    expect(listPublicIssuerIdentities).not.toHaveBeenCalled();
    expect(listRevocationProfiles).not.toHaveBeenCalled();
  });

  it('does not call tenant APIs without an active organization', async () => {
    organizationId = undefined;
    listTrustProfiles.mockResolvedValue([]);
    renderWithRouter(<TrustProfilesPage />);

    await waitFor(() => {
      expect(listTrustProfiles).not.toHaveBeenCalled();
      expect(listPublicIssuerIdentities).not.toHaveBeenCalled();
      expect(listRevocationProfiles).not.toHaveBeenCalled();
    });
  });
});
