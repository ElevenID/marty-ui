/**
 * Integration Tests for API Key Manager
 * 
 * Tests CRUD operations, filtering, and security features for API key management.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { render } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import APIKeyManager from '../APIKeyManager'

// Mock auth hook
vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org_123',
    user: { id: 1, name: 'Admin' },
  }),
}))

const mockApiKeys = [
  {
    id: 'key_1',
    name: 'Production API',
    key_prefix: 'pk_live_',
    masked_key: 'pk_live_••••••••1234',
    scopes: ['read:credentials', 'write:credentials'],
    created_at: '2024-01-01T10:00:00Z',
    last_used: '2024-01-15T14:30:00Z',
    expires_at: null,
    status: 'active',
  },
  {
    id: 'key_2',
    name: 'Webhook Handler',
    key_prefix: 'pk_test_',
    masked_key: 'pk_test_••••••••5678',
    scopes: ['verify:presentations', 'manage:webhooks'],
    created_at: '2024-01-10T12:00:00Z',
    last_used: null,
    expires_at: '2024-12-31T23:59:59Z',
    status: 'active',
  },
  {
    id: 'key_3',
    name: 'Revoked Key',
    key_prefix: 'pk_test_',
    masked_key: 'pk_test_••••••••9999',
    scopes: ['read:credentials'],
    created_at: '2023-12-01T10:00:00Z',
    last_used: '2023-12-15T10:00:00Z',
    expires_at: null,
    status: 'revoked',
    revoked_at: '2024-01-05T10:00:00Z',
  },
]

describe('APIKeyManager', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    
    // Setup default handlers
    server.use(
      http.get('http://localhost:8000/v1/organizations/:orgId/api-keys', ({ params, request }) => {
        const url = new URL(request.url)
        const includeRevoked = url.searchParams.get('includeRevoked') === 'true'
        
        let keys = mockApiKeys.filter((k) => k.status === 'active')
        if (includeRevoked) {
          keys = mockApiKeys
        }
        
        return HttpResponse.json(keys)
      })
    )
  })

  describe('Table Display', () => {
    it('should render API keys table', async () => {
      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText('Production API')).toBeInTheDocument()
      })

      // Table headers
      expect(screen.getByText(/name/i)).toBeInTheDocument()
      expect(screen.getByText(/key/i)).toBeInTheDocument()
      expect(screen.getByText(/scopes/i)).toBeInTheDocument()
      expect(screen.getByText(/created/i)).toBeInTheDocument()
      expect(screen.getByText(/last used/i)).toBeInTheDocument()
    })

    it('should display masked API keys', async () => {
      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText(/pk_live_••••••••1234/)).toBeInTheDocument()
      })
    })

    it('should show scope chips', async () => {
      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText('read:credentials')).toBeInTheDocument()
        expect(screen.getByText('write:credentials')).toBeInTheDocument()
      })
    })

    it('should format dates correctly', async () => {
      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText(/Jan 1, 2024/)).toBeInTheDocument()
      })
    })

    it('should indicate never used keys', async () => {
      render(<APIKeyManager />)

      await waitFor(() => {
        const webhookRow = screen.getByText('Webhook Handler').closest('tr')!
        expect(within(webhookRow).getByText(/never/i)).toBeInTheDocument()
      })
    })
  })

  describe('Filtering', () => {
    it('should hide revoked keys by default', async () => {
      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText('Production API')).toBeInTheDocument()
      })

      expect(screen.queryByText('Revoked Key')).not.toBeInTheDocument()
    })

    it('should toggle showing revoked keys', async () => {
      const user = userEvent.setup()
      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText('Production API')).toBeInTheDocument()
      })

      // Toggle switch
      const showRevokedSwitch = screen.getByLabelText(/show revoked/i)
      await user.click(showRevokedSwitch)

      // Revoked key should now appear
      await waitFor(() => {
        expect(screen.getByText('Revoked Key')).toBeInTheDocument()
      })
    })

    it('should filter expired keys', async () => {
      const user = userEvent.setup()
      
      // Add expired key
      server.use(
        http.get('http://localhost:8000/v1/organizations/:orgId/api-keys', () => {
          return HttpResponse.json([
            ...mockApiKeys.filter((k) => k.status === 'active'),
            {
              id: 'key_4',
              name: 'Expired Key',
              masked_key: 'pk_••••••••0000',
              scopes: ['read:credentials'],
              created_at: '2023-01-01T10:00:00Z',
              expires_at: '2023-12-31T23:59:59Z',
              status: 'expired',
            },
          ])
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => screen.getByText('Production API'))

      const showExpiredSwitch = screen.getByLabelText(/show expired/i)
      await user.click(showExpiredSwitch)

      await waitFor(() => {
        expect(screen.getByText('Expired Key')).toBeInTheDocument()
      })
    })
  })

  describe('Create API Key', () => {
    it('should open create dialog', async () => {
      const user = userEvent.setup()
      render(<APIKeyManager />)

      await waitFor(() => screen.getByRole('button', { name: /create api key/i }))

      const createButton = screen.getByRole('button', { name: /create api key/i })
      await user.click(createButton)

      // Dialog should open
      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(screen.getByText(/new api key/i)).toBeInTheDocument()
    })

    it('should validate key name', async () => {
      const user = userEvent.setup()
      render(<APIKeyManager />)

      await waitFor(() => screen.getByRole('button', { name: /create api key/i }))
      await user.click(screen.getByRole('button', { name: /create api key/i }))

      // Try to create without name
      const createButton = within(screen.getByRole('dialog')).getByRole('button', { name: /create/i })
      await user.click(createButton)

      // Warning should appear
      await waitFor(() => {
        expect(screen.getByText(/enter a key name/i)).toBeInTheDocument()
      })
    })

    it('should validate scopes selection', async () => {
      const user = userEvent.setup()
      render(<APIKeyManager />)

      await waitFor(() => screen.getByRole('button', { name: /create api key/i }))
      await user.click(screen.getByRole('button', { name: /create api key/i }))

      // Enter name but no scopes
      const nameInput = screen.getByLabelText(/key name/i)
      await user.type(nameInput, 'Test Key')

      const createButton = within(screen.getByRole('dialog')).getByRole('button', { name: /create/i })
      await user.click(createButton)

      // Warning should appear
      await waitFor(() => {
        expect(screen.getByText(/select at least one scope/i)).toBeInTheDocument()
      })
    })

    it('should create API key successfully', async () => {
      const user = userEvent.setup()
      
      let createdKey: any
      server.use(
        http.post('http://localhost:8000/v1/organizations/:orgId/api-keys', async ({ request }) => {
          createdKey = await request.json()
          return HttpResponse.json(
            {
              id: 'key_new',
              name: createdKey.name,
              key: 'pk_live_abcdefgh12345678',
              masked_key: 'pk_live_••••••••5678',
              scopes: createdKey.scopes,
              created_at: new Date().toISOString(),
              status: 'active',
            },
            { status: 201 }
          )
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => screen.getByRole('button', { name: /create api key/i }))
      await user.click(screen.getByRole('button', { name: /create api key/i }))

      // Fill form
      await user.type(screen.getByLabelText(/key name/i), 'New Integration Key')
      
      // Select scopes
      const readCredCheckbox = screen.getByLabelText(/read credentials/i)
      await user.click(readCredCheckbox)

      // Create
      const createButton = within(screen.getByRole('dialog')).getByRole('button', { name: /create/i })
      await user.click(createButton)

      // Success message with full key
      await waitFor(() => {
        expect(screen.getByText(/api key created/i)).toBeInTheDocument()
        expect(screen.getByText(/pk_live_abcdefgh12345678/i)).toBeInTheDocument()
      })

      // Verify payload
      expect(createdKey.name).toBe('New Integration Key')
      expect(createdKey.scopes).toContain('read:credentials')
    })

    it('should allow copying new API key', async () => {
      const user = userEvent.setup()
      
      // Moc clipboard
      Object.assign(navigator, {
        clipboard: {
          writeText: vi.fn(() => Promise.resolve()),
        },
      })

      server.use(
        http.post('http://localhost:8000/v1/organizations/:orgId/api-keys', () => {
          return HttpResponse.json({
            id: 'key_new',
            name: 'Test',
            key: 'pk_live_secret123',
            masked_key: 'pk_live_••••••••123',
            scopes: ['read:credentials'],
            created_at: new Date().toISOString(),
            status: 'active',
          })
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => screen.getByRole('button', { name: /create api key/i }))
      await user.click(screen.getByRole('button', { name: /create api key/i }))

      await user.type(screen.getByLabelText(/key name/i), 'Test')
      await user.click(screen.getByLabelText(/read credentials/i))
      
      const createButton = within(screen.getByRole('dialog')).getByRole('button', { name: /create/i })
      await user.click(createButton)

      await waitFor(() => screen.getByText(/pk_live_secret123/i))

      // Copy button
      const copyButton = screen.getByRole('button', { name: /copy/i })
      await user.click(copyButton)

      expect(navigator.clipboard.writeText).toHaveBeenCalledWith('pk_live_secret123')
    })
  })

  describe('Revoke API Key', () => {
    it('should open revoke confirmation', async () => {
      const user = userEvent.setup()
      render(<APIKeyManager />)

      await waitFor(() => screen.getByText('Production API'))

      // Open menu
      const menuButtons = screen.getAllByRole('button', { name: /more/i })
      await user.click(menuButtons[0])

      // Click revoke
      await user.click(screen.getByText(/revoke/i))

      // Confirmation dialog
      expect(screen.getByText(/are you sure/i)).toBeInTheDocument()
    })

    it('should revoke API key', async () => {
      const user = userEvent.setup()
      
      let revokedKeyId: string | undefined
      server.use(
        http.patch('http://localhost:8000/v1/organizations/:orgId/api-keys/:keyId/revoke', ({ params }) => {
          revokedKeyId = params.keyId as string
          return HttpResponse.json({ status: 'revoked' })
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => screen.getByText('Production API'))

      const menuButtons = screen.getAllByRole('button', { name: /more/i })
      await user.click(menuButtons[0])
      await user.click(screen.getByText(/revoke/i))

      // Confirm
      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      await user.click(confirmButton)

      await waitFor(() => {
        expect(revokedKeyId).toBe('key_1')
      })

      // Success message
      expect(screen.getByText(/api key revoked/i)).toBeInTheDocument()
    })
  })

  describe('Delete API Key', () => {
    it('should delete API key', async () => {
      const user = userEvent.setup()
      
      let deletedKeyId: string | undefined
      server.use(
        http.delete('http://localhost:8000/v1/organizations/:orgId/api-keys/:keyId', ({ params }) => {
          deletedKeyId = params.keyId as string
          return HttpResponse.json({ message: 'Deleted' })
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => screen.getByText('Production API'))

      const menuButtons = screen.getAllByRole('button', { name: /more/i })
      await user.click(menuButtons[0])
      await user.click(screen.getByText(/delete/i))

      // Confirm deletion
      const confirmButton = screen.getByRole('button', { name: /delete/i })
      await user.click(confirmButton)

      await waitFor(() => {
        expect(deletedKeyId).toBe('key_1')
      })
    })
  })

  describe('Loading and Error States', () => {
    it('should show loading skeletons', () => {
      server.use(
        http.get('http://localhost:8000/v1/organizations/:orgId/api-keys', () => {
          return new Promise(() => {}) // Never resolves
        })
      )

      render(<APIKeyManager />)

      expect(screen.getAllByRole('progressbar').length).toBeGreaterThan(0)
    })

    it('should handle API errors', async () => {
      server.use(
        http.get('http://localhost:8000/v1/organizations/:orgId/api-keys', () => {
          return HttpResponse.json(
            { error: { message: 'Forbidden' } },
            { status: 403 }
          )
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => {
        expect(screen.getByText(/failed to load api keys/i)).toBeInTheDocument()
      })
    })
  })

  describe('Refresh', () => {
    it('should refresh API keys list', async () => {
      const user = userEvent.setup()
      let fetchCount = 0

      server.use(
        http.get('http://localhost:8000/v1/organizations/:orgId/api-keys', () => {
          fetchCount++
          return HttpResponse.json(mockApiKeys.filter((k) => k.status === 'active'))
        })
      )

      render(<APIKeyManager />)

      await waitFor(() => screen.getByText('Production API'))
      expect(fetchCount).toBe(1)

      // Click refresh
      const refreshButton = screen.getByRole('button', { name: /refresh/i })
      await user.click(refreshButton)

      await waitFor(() => {
        expect(fetchCount).toBe(2)
      })
    })
  })
})
