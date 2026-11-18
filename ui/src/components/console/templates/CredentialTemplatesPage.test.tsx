import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor, within } from '@test/utils'
import CredentialTemplatesPage from './CredentialTemplatesPage'

const { mockListCredentialTemplates, mockListTrustProfiles } = vi.hoisted(() => ({
  mockListCredentialTemplates: vi.fn(),
  mockListTrustProfiles: vi.fn(),
}))

vi.mock('react-i18next', async () => {
  const actual = await vi.importActual<typeof import('react-i18next')>('react-i18next')

  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string, options?: { count?: number, defaultValue?: string }) => key === 'templates.usedByFlows'
        ? `${options?.count} Flow${options?.count === 1 ? '' : 's'}`
        : ['templates.notReported', 'templates.flowUsageNotReported'].includes(key) ? options?.defaultValue || key : key,
    }),
  }
})

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
  listTrustProfiles: (...args: unknown[]) => mockListTrustProfiles(...args),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}))

describe('CredentialTemplatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListTrustProfiles.mockResolvedValue([])
  })

  it('renders safely when credential templates resolve to null', async () => {
    mockListCredentialTemplates.mockResolvedValue(null)

    renderWithRouter(<CredentialTemplatesPage />, {
      initialEntries: ['/console/org/templates/credentials'],
    })

    expect(screen.getByRole('progressbar')).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.getByText('No credential templates yet')).toBeInTheDocument()
    })
  })

  it('renders the native direct-array catalog including later pages', async () => {
    const drafts = Array.from({ length: 100 }, (_, index) => ({ id: `draft-${index}`, name: `Draft ${index}`, claims: [], status: 'draft' }))
    mockListCredentialTemplates.mockResolvedValueOnce(drafts).mockResolvedValueOnce([
        {
          id: 'ct-1',
          name: 'Employee Badge',
          format: 'vc_jwt',
          version: '1.0',
          claims: [{ name: 'employee_id' }],
          issuer_did: 'did:web:issuer.example.com',
          usedByFlowsCount: 2,
          status: 'active',
          updated_at: '2026-04-15T18:00:00Z',
        },
      ])

    renderWithRouter(<CredentialTemplatesPage />, {
      initialEntries: ['/console/org/templates/credentials'],
    })

    await waitFor(() => {
      expect(screen.getByText('Employee Badge')).toBeInTheDocument()
    })

    expect(screen.getByText('VC_JWT')).toBeInTheDocument()
    expect(mockListCredentialTemplates).toHaveBeenLastCalledWith({ organization_id: 'org-1', limit: 100, offset: 100 })
    expect(screen.getByText('templates.issuerDidStatus.configured')).toBeInTheDocument()
  })

  it('distinguishes unreported metadata from a reported version and zero flow usage', async () => {
    mockListCredentialTemplates.mockResolvedValue([
      { id: 'missing', name: 'Absent metadata', claims: [], status: 'draft' },
      { id: 'zero', name: 'Reported zero', version: 0, usedByFlowsCount: 0, claims: [], status: 'draft' },
      { id: 'reported', name: 'Reported metadata', version: '1.0', usedByFlowsCount: 2, claims: [], status: 'active' },
    ])
    const { user } = renderWithRouter(<CredentialTemplatesPage />, { initialEntries: ['/console/org/templates/credentials'] })
    const absentRow = (await screen.findByText('Absent metadata')).closest('tr')!
    const absentCells = within(absentRow).getAllByRole('cell')
    expect(absentCells[2]).toHaveTextContent('Not reported')
    expect(absentCells[5]).toHaveTextContent('Not reported')
    expect(within(absentRow).queryByText('0 Flows')).not.toBeInTheDocument()
    await user.hover(within(absentCells[5]).getByText('Not reported'))
    expect(await screen.findByRole('tooltip')).toHaveTextContent('The service did not report how many flows use this template.')

    const zeroCells = within(screen.getByText('Reported zero').closest('tr')!).getAllByRole('cell')
    expect(zeroCells[2]).toHaveTextContent(/^0$/)
    expect(zeroCells[5]).toHaveTextContent('0 Flows')
    const reportedCells = within(screen.getByText('Reported metadata').closest('tr')!).getAllByRole('cell')
    expect(reportedCells[2]).toHaveTextContent('1.0')
    expect(reportedCells[5]).toHaveTextContent('2 Flows')
    expect(mockListCredentialTemplates).toHaveBeenCalledExactlyOnceWith({ organization_id: 'org-1', limit: 100, offset: 0 })
  })

  it.each([null, '', '   '])('shows an explicit unreported version for an empty value: %s', async (version) => {
    mockListCredentialTemplates.mockResolvedValue([{ id: 'ct-empty', name: 'Empty version', version, claims: [], status: 'draft' }])
    renderWithRouter(<CredentialTemplatesPage />, { initialEntries: ['/console/org/templates/credentials'] })
    const row = (await screen.findByText('Empty version')).closest('tr')!
    expect(within(row).getAllByRole('cell')[2]).toHaveTextContent('Not reported')
  })
})
