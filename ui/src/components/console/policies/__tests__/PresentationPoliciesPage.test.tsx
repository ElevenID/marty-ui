import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { renderWithRouter } from '@test/utils'
import PresentationPoliciesPage from '../PresentationPoliciesPage'

const { listPolicies } = vi.hoisted(() => ({ listPolicies: vi.fn() }))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, options: { defaultValue?: string } = {}) => options.defaultValue || key }),
}))
vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-recovery' }),
}))
vi.mock('../../../../services/presentationPolicyApi', () => ({
  listPresentationPolicies: (...args: unknown[]) => listPolicies(...args),
  listCredentialTemplates: async () => [{ id: 'template' }],
  listTrustProfiles: async () => [{ id: 'trust' }],
}))
vi.mock('../../../common', () => ({
  ResourcePage: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  EmptyState: () => <p>No presentation policies</p>,
  EmptyStates: { policies: {} },
  StatusChip: ({ status }: { status: string }) => <span>{status}</span>,
}))

describe('PresentationPoliciesPage API recovery', () => {
  beforeEach(() => listPolicies.mockReset())

  it('keeps an initial list outage in the page and retries the scoped request', async () => {
    listPolicies.mockRejectedValueOnce(new Error('Policy service temporarily unavailable'))
      .mockResolvedValueOnce([{
        id: 'policy', name: 'Recovered member policy', trustProfile: 'Trusted issuer',
        requiredClaims: ['memberId'], freshness: '1 day', holderBinding: true,
        usageCount: 0, status: 'active',
      }])

    renderWithRouter(<PresentationPoliciesPage />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Policy service temporarily unavailable')
    expect(screen.queryByText('No presentation policies')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Recovered member policy')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(listPolicies).toHaveBeenCalledTimes(2)
    expect(listPolicies).toHaveBeenNthCalledWith(1, { organization_id: 'org-recovery' })
    expect(listPolicies).toHaveBeenNthCalledWith(2, { organization_id: 'org-recovery' })
  })

  it('shows the empty state only after a successful empty response', async () => {
    listPolicies.mockResolvedValue([])
    renderWithRouter(<PresentationPoliciesPage />)
    expect(await screen.findByText('No presentation policies')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })
})
