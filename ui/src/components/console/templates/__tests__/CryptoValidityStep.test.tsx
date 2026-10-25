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

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

describe('CryptoValidityStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it.each([[1, 1], [3600, 1], [86399, 1], [86400, 1], [86401, 2]])('shows the effective whole-day duration for %s seconds', (seconds, days) => {
    mockUseAsyncData.mockReturnValue({ data: [], loading: false, error: null });
    renderWithoutRouter(<CryptoValidityStep data={{ validity_rules: { ttl_seconds: seconds, max_validity_seconds: seconds, not_before_offset: 900 } }} onChange={vi.fn()} />);
    const inputs = screen.getAllByRole('spinbutton');
    expect(inputs[0]).toHaveValue(days);
    expect(inputs[1]).toHaveValue(days);
    expect(inputs[2]).toHaveValue(900);
    expect(screen.getByText(/Seconds-based durations round up/)).toBeInTheDocument();
  });

  it('treats null revocation profile data as an empty list', () => {
    mockUseAsyncData.mockReturnValue({
      data: null,
      loading: false,
      error: null,
      reload: vi.fn(),
    })

    renderWithoutRouter(
      <CryptoValidityStep
        data={{
          validity_rules: {
            ttl_seconds: 31536000,
            not_before_offset: 0,
            max_validity_seconds: 63072000,
          },
        }}
        onChange={vi.fn()}
      />
    )

    expect(screen.getAllByText('Revocation Profile').length).toBeGreaterThan(0)
    expect(screen.queryByText(/signing algorithm/i)).not.toBeInTheDocument()
  })
})
