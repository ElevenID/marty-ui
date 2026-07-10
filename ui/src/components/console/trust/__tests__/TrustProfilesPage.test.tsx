import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import TrustProfilesPage from '../TrustProfilesPage'

const listTrustProfiles = vi.fn()
const listRevocationProfiles = vi.fn()
const listSigningKeys = vi.fn()
const listIssuerProfiles = vi.fn()
const getKeyManagementConfig = vi.fn()

const translations: Record<string, string> = {
  'trust.trustProfiles': 'Trust Profiles',
  'trust.trustProfilesDescription': 'Manage trust profiles.',
  'trust.tableHeaders.name': 'Name',
  'trust.tableHeaders.framework': 'Framework',
  'trust.tableHeaders.status': 'Status',
  'trust.tableHeaders.trustedIssuers': 'Trusted Issuers',
  'trust.tableHeaders.validationRules': 'Cryptographic Policy',
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

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: authState.organizationId }),
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listTrustProfiles: (...args: unknown[]) => listTrustProfiles(...args),
  listRevocationProfiles: (...args: unknown[]) => listRevocationProfiles(...args),
}))

vi.mock('../../../../services/signingKeysApi', () => ({
  listSigningKeys: (...args: unknown[]) => listSigningKeys(...args),
  listIssuerProfiles: (...args: unknown[]) => listIssuerProfiles(...args),
  getKeyManagementConfig: (...args: unknown[]) => getKeyManagementConfig(...args),
}))

vi.mock('../../../common', () => ({
  ResourcePage: ({ children, title, tabs }: { children: React.ReactNode; title: string; tabs?: Array<{ label: string }> }) => (
    <div>
      <h1>{title}</h1>
      {tabs?.length ? <div data-testid="resource-tabs">{tabs.map((tab) => tab.label).join(',')}</div> : null}
      {children}
    </div>
  ),
  StatusChip: ({ status }: { status: string }) => <span>{status}</span>,
  EmptyState: ({ title, prerequisites }: { title?: string; prerequisites?: Array<{ label: string; status: string }> }) => (
    <div>
      <div>{title || 'empty-state'}</div>
      {prerequisites?.map((prereq) => (
        <span key={prereq.label}>{`${prereq.label}:${prereq.status}`}</span>
      ))}
    </div>
  ),
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
    listRevocationProfiles.mockResolvedValue([])
    listSigningKeys.mockResolvedValue({ keys: [] })
    listIssuerProfiles.mockResolvedValue({ profiles: [] })
    getKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: null,
      services: [],
    })
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

    await waitFor(() => {
      expect(listSigningKeys).toHaveBeenCalledWith({ organization_id: 'org-1', limit: 1 })
      expect(listIssuerProfiles).toHaveBeenCalledWith({ organization_id: 'org-1' })
      expect(getKeyManagementConfig).toHaveBeenCalledWith({ organization_id: 'org-1' })
      expect(listRevocationProfiles).toHaveBeenCalledWith({ organization_id: 'org-1', limit: 1 })
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
      expect(listSigningKeys).not.toHaveBeenCalled()
      expect(listIssuerProfiles).not.toHaveBeenCalled()
      expect(getKeyManagementConfig).not.toHaveBeenCalled()
      expect(listRevocationProfiles).not.toHaveBeenCalled()
    })
  })

  it('shows trust profile prerequisites in empty state', async () => {
    listTrustProfiles.mockResolvedValue([])
    listSigningKeys.mockResolvedValue({ keys: [] })
    listIssuerProfiles.mockResolvedValue({ profiles: [] })
    getKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: null,
      services: [],
    })
    listRevocationProfiles.mockResolvedValue([])

    renderWithRouter(<TrustProfilesPage />)

    expect(await screen.findByText('No trust profiles')).toBeInTheDocument()
    expect(screen.getByText('Key Management Service:missing')).toBeInTheDocument()
    expect(screen.getByText('Issuer Identity or Signing Key:missing')).toBeInTheDocument()
    expect(screen.getByText('Revocation Profile:missing')).toBeInTheDocument()
  })

  it('surfaces trust prerequisite load failures as errors instead of missing setup', async () => {
    listTrustProfiles.mockResolvedValue([])
    listSigningKeys.mockRejectedValue(new Error('KMS unavailable'))
    listIssuerProfiles.mockResolvedValue({ profiles: [] })
    getKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: null,
      services: [],
    })
    listRevocationProfiles.mockRejectedValue(new Error('Revocation service unavailable'))

    renderWithRouter(<TrustProfilesPage />)

    expect(await screen.findByText('No trust profiles')).toBeInTheDocument()
    expect(screen.getByText('Key Management Service:error')).toBeInTheDocument()
    expect(screen.getByText('Revocation Profile:error')).toBeInTheDocument()
    expect(screen.getByText(/KMS unavailable/)).toBeInTheDocument()
    expect(screen.getByText(/Revocation service unavailable/)).toBeInTheDocument()
  })

  it('treats managed issuer prerequisites as ready when KMS and issuer input exist', async () => {
    listTrustProfiles.mockResolvedValue([])
    listSigningKeys.mockResolvedValue({
      keys: [
        {
          id: 'key-1',
          name: 'Issuer key',
        },
      ],
    })
    listIssuerProfiles.mockResolvedValue({ profiles: [] })
    getKeyManagementConfig.mockResolvedValue({
      supports_native_key_management: false,
      default_service_id: 'managed-openbao-transit',
      services: [
        {
          id: 'managed-openbao-transit',
          name: 'Managed OpenBao',
          service_type: 'openbao-transit',
          status: 'configured',
        },
      ],
    })
    listRevocationProfiles.mockResolvedValue([])

    renderWithRouter(<TrustProfilesPage />)

    expect(await screen.findByText('No trust profiles')).toBeInTheDocument()
    expect(screen.getByText('Key Management Service:ready')).toBeInTheDocument()
    expect(screen.getByText('Issuer Identity or Signing Key:ready')).toBeInTheDocument()
  })

  it('renders as a standalone page without top-level trust tabs', async () => {
    listTrustProfiles.mockResolvedValue([])

    renderWithRouter(<TrustProfilesPage />)

    expect(await screen.findByText('No trust profiles')).toBeInTheDocument()
    expect(screen.queryByTestId('resource-tabs')).not.toBeInTheDocument()
  })
})
