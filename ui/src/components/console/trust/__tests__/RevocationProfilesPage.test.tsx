import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import RevocationProfilesPage from '../RevocationProfilesPage'

const listRevocationProfiles = vi.fn()

const translations: Record<string, string> = {
  'trust.revocationProfiles': 'Revocation Profiles',
  'trust.revocationProfilesDescription': 'Manage revocation profiles.',
  'trust.revocationProfile': 'Revocation Profile',
  'trust.breadcrumbs.console': 'Console',
  'trust.breadcrumbs.trust': 'Trust',
  'trust.breadcrumbs.revocationProfiles': 'Revocation Profiles',
  'common.errorLoading': 'Failed to load revocation profiles.',
  'trust.noRevocationProfiles': 'No revocation profiles configured.',
}

let authState = { organizationId: 'org-1' }

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, defaultOrOptions?: string | Record<string, unknown>) => {
      if (typeof defaultOrOptions === 'string') {
        return defaultOrOptions
      }
      return String(defaultOrOptions?.defaultValue || translations[key] || key)
    },
  }),
}))

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => authState,
}))

vi.mock('../../../../services/presentationPolicyApi', () => ({
  listRevocationProfiles: (...args: unknown[]) => listRevocationProfiles(...args),
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
  EmptyState: ({ title }: { title?: string }) => <div>{title || 'empty-state'}</div>,
  EmptyStates: {
    revocationProfiles: { title: 'No revocation profiles configured.' },
  },
}))

describe('RevocationProfilesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authState = { organizationId: 'org-1' }
  })

  it('loads organization-scoped revocation profiles', async () => {
    listRevocationProfiles.mockResolvedValue([
      {
        id: 'rev-1',
        name: 'Production revocation',
        check_mode: 'HARD_FAIL',
        revocation_mechanism: ['StatusList2021'],
        status_list_url: 'https://example.com/status/1',
        updated_at: '2024-01-01T00:00:00Z',
      },
    ])

    renderWithRouter(<RevocationProfilesPage />)

    await waitFor(() => {
      expect(listRevocationProfiles).toHaveBeenCalledWith(
        { organization_id: 'org-1' },
        { retryConfig: { maxRetries: 0 } },
      )
    })

    expect(await screen.findByText('Production revocation')).toBeInTheDocument()
    expect(screen.getByText('HARD_FAIL')).toBeInTheDocument()
  })

  it('shows empty state instead of an error when the revocation service returns 503', async () => {
    const unavailableError = Object.assign(new Error('Service unavailable'), { status: 503 })
    listRevocationProfiles.mockRejectedValue(unavailableError)

    renderWithRouter(<RevocationProfilesPage />)

    expect(await screen.findByText('No revocation profiles configured.')).toBeInTheDocument()
    expect(screen.queryByText('Failed to load revocation profiles.')).not.toBeInTheDocument()
  })

  it('renders as a standalone page without top-level trust tabs', async () => {
    listRevocationProfiles.mockResolvedValue([])

    renderWithRouter(<RevocationProfilesPage />)

    expect(await screen.findByText('No revocation profiles configured.')).toBeInTheDocument()
    expect(screen.queryByTestId('resource-tabs')).not.toBeInTheDocument()
  })
})