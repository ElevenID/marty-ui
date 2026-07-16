import { describe, expect, it, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithoutRouter } from '@test/utils'

import CryptoValidityStep from '../steps/CryptoValidityStep'

const { mockUseAsyncData } = vi.hoisted(() => ({
  mockUseAsyncData: vi.fn(),
}))

vi.mock('../../../../hooks/useAsyncData', () => ({
  useAsyncData: (...args: unknown[]) => mockUseAsyncData(...args),
}))

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-123' }),
}))

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

describe('CryptoValidityStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('treats null revocation profile data as an empty list in advanced options', async () => {
    mockUseAsyncData.mockReturnValue({
      data: null,
      loading: false,
      error: null,
      reload: vi.fn(),
    })

    const { user } = renderWithoutRouter(
      <CryptoValidityStep
        data={{
          validity_rules: {
            ttl_seconds: 31536000,
            not_before_offset: 0,
            max_validity_seconds: 63072000,
          },
          signing_algorithm: 'ES256',
        }}
        onChange={vi.fn()}
      />
    )

    await user.click(screen.getByRole('button', { name: /advanced cryptographic options/i }))

    expect((await screen.findAllByText('Revocation Profile')).length).toBeGreaterThan(0)
  })
})
