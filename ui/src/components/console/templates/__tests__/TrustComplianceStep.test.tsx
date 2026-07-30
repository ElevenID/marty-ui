import { describe, expect, it, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router'
import { screen, waitFor } from '@testing-library/react'
import { renderWithoutRouter } from '@test/utils'

import TrustComplianceStep from '../steps/TrustComplianceStep'

const { mockUseAsyncData } = vi.hoisted(() => ({
  mockUseAsyncData: vi.fn(),
}))

vi.mock('../../../../hooks/useAsyncData', () => ({
  useAsyncData: (...args: unknown[]) => mockUseAsyncData(...args),
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

describe('TrustComplianceStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('treats null async data as empty lists instead of crashing', () => {
    mockUseAsyncData
      .mockReturnValueOnce({
        data: null,
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: null,
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: null,
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: null }}
          onChange={vi.fn()}
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/trust profile required/i)).toBeInTheDocument()
  })

  it('loads and auto-selects the sole required active compliance profile', async () => {
    const onChange = vi.fn()
    mockUseAsyncData
      .mockReturnValueOnce({
        data: [{ id: 'trust-1', name: 'Production Trust', status: 'active' }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [{
          issuer_did: 'did:web:issuer.example.com',
          key_purpose: 'vc_jwt_issuer',
          algorithm: 'ES256',
          status: 'active',
        }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [
          { id: 'compliance-1', name: 'OID4VC Core', compliance_code: 'OID4VC', status: 'ACTIVE', is_system: true, discoverable: true },
        ],
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: 'trust-1', issuer_did: 'did:web:issuer.example.com' }}
          onChange={onChange}
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/1 active compliance profile available/i)).toBeInTheDocument()
    expect(screen.getByTestId('template-compliance-profile-select').parentElement?.querySelector('input')).toBeRequired()
    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith({ compliance_profile_id: 'compliance-1' })
    })
    expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument()
  })

  it('does not offer malformed public issuer identities', () => {
    mockUseAsyncData
      .mockReturnValueOnce({
        data: [{ id: 'trust-1', name: 'Production Trust', status: 'active' }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [{
          issuer_did: 'not-a-did',
          key_purpose: 'vc_jwt_issuer',
          algorithm: 'ES256',
          status: 'active',
        }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [],
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: 'trust-1' }}
          onChange={vi.fn()}
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/active issuer DID required/i)).toBeInTheDocument()
    expect(screen.getByText(/organization registry resolves its managed custody profile/i)).toBeInTheDocument()
    expect(screen.queryByText(/optional compliance profile/i)).not.toBeInTheDocument()
  })

  it('auto-selects a single issuer DID without exposing custody routing', async () => {
    const onChange = vi.fn()
    mockUseAsyncData
      .mockReturnValueOnce({
        data: [{ id: 'trust-1', name: 'Production Trust', status: 'active' }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [{
          issuer_did: 'did:web:issuer.example.com',
          key_purpose: 'vc_jwt_issuer',
          algorithm: 'ES256',
          status: 'active',
        }],
        loading: false,
        error: null,
        reload: vi.fn(),
      })
      .mockReturnValueOnce({
        data: [],
        loading: false,
        error: null,
        reload: vi.fn(),
      })

    renderWithoutRouter(
      <MemoryRouter>
        <TrustComplianceStep
          data={{ trust_profile_id: 'trust-1', issuer_did: null }}
          onChange={onChange}
        />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith({
        issuer_did: 'did:web:issuer.example.com',
      })
    })
    const patchKeys = onChange.mock.calls.flatMap(([patch]) => Object.keys(patch))
    expect(patchKeys).not.toContain('issuer_profile_id')
    expect(patchKeys).not.toContain('signing_algorithm')
  })
})
