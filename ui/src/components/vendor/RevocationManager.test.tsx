import { describe, expect, it, vi } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'

import RevocationManager from './RevocationManager'

const authState = vi.hoisted(() => ({
  organizationId: '',
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => authState,
}))

describe('RevocationManager', () => {
  it('does not leave revocation views loading forever when organization context is missing', async () => {
    const { user } = renderWithRouter(<RevocationManager />)

    await waitFor(() => {
      expect(screen.getByText(/active organization is required/i)).toBeInTheDocument()
    })
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /history/i }))

    expect(await screen.findByText(/active organization is required/i)).toBeInTheDocument()
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
  })
})
