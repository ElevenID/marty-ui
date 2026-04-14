import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import SigningKeysPage from './SigningKeysPage'

const {
  mockCan,
  mockShowNotification,
  mockListSigningKeys,
  mockCreateSigningKey,
  mockRotateSigningKey,
  mockDeleteSigningKey,
  mockGetKeyManagementConfig,
  mockUpdateKeyManagementConfig,
} = vi.hoisted(() => ({
  mockCan: vi.fn(),
  mockShowNotification: vi.fn(),
  mockListSigningKeys: vi.fn(),
  mockCreateSigningKey: vi.fn(),
  mockRotateSigningKey: vi.fn(),
  mockDeleteSigningKey: vi.fn(),
  mockGetKeyManagementConfig: vi.fn(),
  mockUpdateKeyManagementConfig: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listSigningKeys: (...args: unknown[]) => mockListSigningKeys(...args),
    createSigningKey: (...args: unknown[]) => mockCreateSigningKey(...args),
    rotateSigningKey: (...args: unknown[]) => mockRotateSigningKey(...args),
    deleteSigningKey: (...args: unknown[]) => mockDeleteSigningKey(...args),
    getKeyManagementConfig: (...args: unknown[]) => mockGetKeyManagementConfig(...args),
    updateKeyManagementConfig: (...args: unknown[]) => mockUpdateKeyManagementConfig(...args),
  },
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({
    can: mockCan,
    getPermissionMessage: () => 'permission denied',
  }),
}))

describe('SigningKeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCan.mockImplementation((resource: string, action: string) => {
      if (resource === 'signing-key' && (action === 'create' || action === 'delete')) {
        return true
      }

      return false
    })
    mockListSigningKeys.mockResolvedValue([])
    mockCreateSigningKey.mockResolvedValue({ id: 'key_new' })
    mockRotateSigningKey.mockResolvedValue({ id: 'key_new' })
    mockDeleteSigningKey.mockResolvedValue({ ok: true })
    mockGetKeyManagementConfig.mockResolvedValue({
      hsm_enabled: false,
      hsm_settings: {},
      vault_enabled: false,
      vault_settings: {},
    })
    mockUpdateKeyManagementConfig.mockResolvedValue({ ok: true })
  })

  it('opens the upload dialog from the empty-state action for deploy admins', async () => {
    const { user } = renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/signing-keys'],
    })

    await waitFor(() => {
      expect(screen.getByText('deploy.signingKeys.emptyState.title')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'deploy.signingKeys.emptyState.actionLabel' }))

    expect(screen.getByText('deploy.signingKeys.uploadDialog.title')).toBeInTheDocument()
  })

  it('developer and operator release personas can inspect keys but cannot rotate or delete them', async () => {
    mockCan.mockReturnValue(false)
    mockListSigningKeys.mockResolvedValue([
      {
        id: 'key_123456789',
        name: 'Issuer Key',
        algorithm: 'ES256',
        status: 'active',
        expiry_date: '2030-01-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z',
      },
    ])

    renderWithRouter(<SigningKeysPage />, {
      initialEntries: ['/console/org/deploy/signing-keys'],
    })

    await waitFor(() => {
      expect(screen.getByText('Issuer Key')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'deploy.signingKeys.hsmVaultSettings' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'deploy.signingKeys.uploadKey' })).toBeDisabled()
    expect(screen.queryByTestId('RefreshIcon')).not.toBeInTheDocument()
    expect(screen.queryByTestId('DeleteIcon')).not.toBeInTheDocument()
  })
})