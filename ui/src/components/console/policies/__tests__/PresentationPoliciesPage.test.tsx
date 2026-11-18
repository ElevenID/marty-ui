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
        id: 'policy', name: 'Recovered member policy', trust_profile_id: '60000000-0000-0000-0000-000000000001',
        required_claims: [{ claim_name: 'memberId', display_name: 'Member ID' }],
        credential_requirements: [], alternative_requirements: [],
        freshness: { max_age_seconds: 86400, require_not_revoked: true },
        holder_binding: { required: true }, status: 'active',
      }])

    renderWithRouter(<PresentationPoliciesPage />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Policy service temporarily unavailable')
    expect(screen.queryByText('No presentation policies')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Recovered member policy')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(listPolicies).toHaveBeenCalledTimes(2)
    expect(listPolicies).toHaveBeenNthCalledWith(1, { organization_id: 'org-recovery', limit: 100, offset: 0 })
    expect(listPolicies).toHaveBeenNthCalledWith(2, { organization_id: 'org-recovery', limit: 100, offset: 0 })
  })

  it('shows the empty state only after a successful empty response', async () => {
    listPolicies.mockResolvedValue([])
    renderWithRouter(<PresentationPoliciesPage />)
    expect(await screen.findByText('No presentation policies')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it('renders canonical nested requirements and optional binding without inventing usage', async () => {
    listPolicies.mockResolvedValue([{
      id: 'age-proof', name: 'Private Online Age Proof', status: 'active',
      required_claims: [],
      credential_requirements: [{
        credential_template_id: '50000000-0000-0000-0000-000000000020',
        display_name: 'Mobile Driving Licence',
        trust_profile_id: '60000000-0000-0000-0000-000000000001',
        requested_claims: [{ claim_name: 'age_over_21', required: true }],
      }],
      alternative_requirements: [{ name: 'Alternative identity', min_satisfied: 1, credential_requirements: [] }],
      holder_binding: { required: false },
    }])
    renderWithRouter(<PresentationPoliciesPage />)
    expect(await screen.findByText('Private Online Age Proof')).toBeInTheDocument()
    expect(screen.getByText('60000000-0000-0000-0000-000000000001')).toBeInTheDocument()
    expect(screen.getByText('1 credential requirement')).toBeInTheDocument()
    expect(screen.getByText('1 alternative group')).toBeInTheDocument()
    expect(screen.getByText('policies.holderBinding.optional')).toBeInTheDocument()
    expect(screen.queryByText('policies.tableHeaders.usage')).not.toBeInTheDocument()
  })
})
