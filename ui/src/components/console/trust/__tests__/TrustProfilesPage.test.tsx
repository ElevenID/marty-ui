import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import TrustProfilesPage from '../TrustProfilesPage'

const listTrustProfiles = vi.fn()

const translations: Record<string, string> = {
  'trust.trustProfiles': 'Trust Profiles',
  'trust.trustProfilesDescription': 'Manage trust profiles.',
  'trust.tableHeaders.name': 'Name',
  'trust.tableHeaders.framework': 'Framework',
  'trust.tableHeaders.status': 'Status',
  'trust.tableHeaders.trustedIssuers': 'Trusted Issuers',
  'trust.tableHeaders.validationRules': 'Validation Rules',
  'trust.tableHeaders.lastUpdated': 'Last Updated',
  'trust.tableHeaders.actions': 'Actions',
  'trust.actions.viewDetails': 'View details',
  'trust.actions.edit': 'Edit',
  'trust.failedToLoad': 'Failed to load trust profiles.',
  'trust.breadcrumbs.console': 'Console',
  'trust.breadcrumbs.trust': 'Trust',
  'trust.breadcrumbs.trustProfiles': 'Trust Profiles',
  'trust.trustedIssuers': 'Trusted Issuers',
  'trust.revocationProfiles': 'Revocation Profiles',
}

let authState = { organizationId: 'org-1' }

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options: Record<string, unknown> = {}) => String(options.defaultValue || translations[key] || key),
  }),
}))

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => authState,
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listTrustProfiles: (...args: unknown[]) => listTrustProfiles(...args),
}))

vi.mock('../../../common', () => ({
  ResourcePage: ({ children, title }: { children: React.ReactNode; title: string }) => (
    <div>
      <h1>{title}</h1>
      {children}
    </div>
  ),
  StatusChip: ({ status }: { status: string }) => <span>{status}</span>,
  EmptyState: ({ title }: { title?: string }) => <div>{title || 'empty-state'}</div>,
  EmptyStates: {
    trustProfiles: { title: 'No trust profiles' },
  },
}))

vi.mock('../../../trust', () => ({
  TrustProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

describe('TrustProfilesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authState = { organizationId: 'org-1' }
  })

  it('loads organization-scoped profiles and renders canonical fields', async () => {
    listTrustProfiles.mockResolvedValue([
      {
        id: 'profile-1',
        name: 'Production Trust',
        framework: 'custom',
        status: 'active',
        trusted_issuers: [{ id: 'issuer-1' }],
        validation_rules: { allowed_algorithms: ['ES256', 'EdDSA'] },
        updated_at: '2024-01-01T00:00:00Z',
      },
    ])

    renderWithRouter(<TrustProfilesPage />)

    await waitFor(() => {
      expect(listTrustProfiles).toHaveBeenCalledWith({ organization_id: 'org-1' })
    })

    expect(await screen.findByText('Production Trust')).toBeInTheDocument()
    expect(screen.getByText('CUSTOM')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('does not call the API when organization context is missing', async () => {
    authState = { organizationId: undefined }

    renderWithRouter(<TrustProfilesPage />)

    await waitFor(() => {
      expect(listTrustProfiles).not.toHaveBeenCalled()
    })
  })
})