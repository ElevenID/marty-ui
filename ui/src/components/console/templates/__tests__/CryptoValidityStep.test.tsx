import { describe, expect, it, vi, beforeEach } from 'vitest'
import { useState } from 'react'
import { screen } from '@testing-library/react'
import { renderWithoutRouter } from '@test/utils'

import CryptoValidityStep from '../steps/CryptoValidityStep'
import { INITIAL_TEMPLATE_VALIDITY } from '../credentialTemplateValidity'

function ValidityEditor() {
  const [data, setData] = useState({ validity_rules: { ...INITIAL_TEMPLATE_VALIDITY } });
  return <CryptoValidityStep data={data} onChange={(updates: object) => setData((current) => ({ ...current, ...updates }))} />;
}

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
    mockUseAsyncData.mockReturnValue({ data: [], loading: false, error: null });
  })

  it('keeps an empty draft editable and validates values without replacing them with a fallback', async () => {
    const { user } = renderWithoutRouter(<ValidityEditor />);
    const days = screen.getByRole('spinbutton', { name: /Default Validity/ });
    await user.clear(days);
    expect(days).toHaveValue(null);
    expect(days).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText('Enter a whole number of days from 1 to 2147483647.')).toBeInTheDocument();
    for (const value of ['0', '-1', '1.5', '2147483648']) {
      await user.clear(days); await user.type(days, value);
      expect(days).toHaveValue(Number(value));
      expect(days).toHaveAttribute('aria-invalid', 'true');
    }
    await user.clear(days); await user.type(days, '31');
    expect(days).toHaveValue(31);
    expect(days).toHaveAttribute('aria-invalid', 'false');
    expect(screen.queryByText('Enter a whole number of days from 1 to 2147483647.')).not.toBeInTheDocument();
    const offset = screen.getByRole('spinbutton', { name: /Not Before Offset/ });
    await user.clear(offset); await user.type(offset, '-900');
    expect(offset).toHaveValue(-900);
    expect(offset).toHaveAttribute('aria-invalid', 'false');
  });

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
