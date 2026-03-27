import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import TrustedIssuersPage from '../TrustedIssuersPage'

const listTrustProfiles = vi.fn()
const listTrustProfileIssuers = vi.fn()

const translations: Record<string, string> = {
  'trust.trustedIssuers': 'Trusted Issuers',
  'trust.trustedIssuersDescription': 'Manage trusted issuers.',
  'trust.trustedIssuersPage.searchPlaceholder': 'Search issuers',
  'trust.trustedIssuersPage.tableHeaders.name': 'Name',
  'trust.trustedIssuersPage.tableHeaders.country': 'Country',
  'trust.trustedIssuersPage.tableHeaders.did': 'DID',
  'trust.trustedIssuersPage.tableHeaders.trustProfile': 'Trust Profile',
  'trust.trustedIssuersPage.tableHeaders.status': 'Status',
  'trust.trustedIssuersPage.tableHeaders.actions': 'Actions',
  'trust.trustedIssuersPage.status.active': 'Active',
  'trust.trustedIssuersPage.status.inactive': 'Inactive',
  'trust.trustedIssuersPage.actions.viewDetails': 'View details',
  'trust.trustedIssuersPage.actions.remove': 'Remove',
  'trust.trustedIssuersPage.empty': 'No issuers match your search.',
  'trust.breadcrumbs.console': 'Console',
  'trust.breadcrumbs.trust': 'Trust',
  'trust.breadcrumbs.trustedIssuers': 'Trusted Issuers',
  'trust.trustProfiles': 'Trust Profiles',
  'trust.revocationProfiles': 'Revocation Profiles',
  'actions.add': 'Add',
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
  listTrustProfileIssuers: (...args: unknown[]) => listTrustProfileIssuers(...args),
}))

vi.mock('../../../common', () => ({
  ResourcePage: ({ children, title, actions }: { children: React.ReactNode; title: string; actions?: React.ReactNode }) => (
    <div>
      <h1>{title}</h1>
      {actions}
      {children}
    </div>
  ),
  AddButton: ({ label, path }: { label: string; path: string }) => <a href={path}>{label}</a>,
  EmptyState: ({ title }: { title?: string }) => <div>{title || 'empty-state'}</div>,
  EmptyStates: {
    trustedIssuers: { title: 'No trusted issuers' },
  },
}))

describe('TrustedIssuersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authState = { organizationId: 'org-1' }
  })

  it('loads issuers through organization-scoped profile and issuer endpoints', async () => {
    listTrustProfiles.mockResolvedValue([
      { id: 'profile-1', name: 'Production Trust' },
      { id: 'profile-2', name: 'Partner Trust' },
    ])
    listTrustProfileIssuers
      .mockResolvedValueOnce([
        { id: 'issuer-1', name: 'Alpha Issuer', did: 'did:web:alpha.example.com', status: 'trusted', country: 'US' },
      ])
      .mockResolvedValueOnce([
        { id: 'issuer-2', name: 'Beta Issuer', did: 'did:web:beta.example.com', status: 'inactive' },
      ])

    const { user } = renderWithRouter(<TrustedIssuersPage />)

    await waitFor(() => {
      expect(listTrustProfiles).toHaveBeenCalledWith({ organization_id: 'org-1' })
    })
    await waitFor(() => {
      expect(listTrustProfileIssuers).toHaveBeenCalledWith('profile-1')
      expect(listTrustProfileIssuers).toHaveBeenCalledWith('profile-2')
    })

    expect(await screen.findByText('Alpha Issuer')).toBeInTheDocument()
    expect(screen.getByText('Production Trust')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Inactive')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()

    await user.type(screen.getByPlaceholderText('Search issuers'), 'beta')

    expect(screen.queryByText('Alpha Issuer')).not.toBeInTheDocument()
    expect(screen.getByText('Beta Issuer')).toBeInTheDocument()
  })

  it('does not fetch issuers when organization context is missing', async () => {
    authState = { organizationId: undefined }

    renderWithRouter(<TrustedIssuersPage />)

    await waitFor(() => {
      expect(listTrustProfiles).not.toHaveBeenCalled()
      expect(listTrustProfileIssuers).not.toHaveBeenCalled()
    })
  })
})