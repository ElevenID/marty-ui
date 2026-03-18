import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@test/utils'

import { BiometricCapture } from '../applicantVetting/BiometricCapture'

describe('BiometricCapture', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('shows a camera permission error when media access fails', async () => {
    const getUserMedia = vi.fn().mockRejectedValue(new Error('denied'))
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia },
    })

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { user } = render(<BiometricCapture biometricType="IRIS" />)

    expect(screen.getByText('IRIS Capture')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Start Camera' }))

    expect(await screen.findByText('Failed to access camera. Please grant camera permissions.')).toBeInTheDocument()
    expect(getUserMedia).toHaveBeenCalled()

    consoleSpy.mockRestore()
  })
})