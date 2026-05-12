import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import CredentialTemplatesPage from './CredentialTemplatesPage'

const { mockListCredentialTemplates } = vi.hoisted(() => ({
  mockListCredentialTemplates: vi.fn(),
}))

vi.mock('react-i18next', async () => {
  const actual = await vi.importActual<typeof import('react-i18next')>('react-i18next')

  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => key,
    }),
  }
})

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}))

describe('CredentialTemplatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
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

  it('renders listed templates from a wrapped response shape', async () => {
    mockListCredentialTemplates.mockResolvedValue({
      items: [
        {
          id: 'ct-1',
          name: 'Employee Badge',
          format: 'vc_jwt',
          version: '1.0',
          claims: [{ name: 'employee_id' }],
          hasArtifacts: true,
          artifactsValidated: true,
          usedByFlowsCount: 2,
          status: 'active',
          updated_at: '2026-04-15T18:00:00Z',
        },
      ],
    })

    renderWithRouter(<CredentialTemplatesPage />, {
      initialEntries: ['/console/org/templates/credentials'],
    })

    await waitFor(() => {
      expect(screen.getByText('Employee Badge')).toBeInTheDocument()
    })

    expect(screen.getByText('VC_JWT')).toBeInTheDocument()
  })
})
