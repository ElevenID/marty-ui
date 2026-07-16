import { describe, expect, it, vi } from 'vitest'

import {
  formatMyDocumentDate,
  getMyDocumentDisplayName,
  getMyDocumentExpiryDate,
  getMyDocumentIssueDate,
  getMyDocumentNationality,
  getMyDocumentStatus,
  isMyDocumentExpired,
  isMyDocumentExpiringSoon,
  loadMyDocuments,
} from './myDocuments'

describe('myDocuments helpers', () => {
  it('formats document dates safely', () => {
    expect(formatMyDocumentDate(null)).toBe('N/A')
    expect(formatMyDocumentDate('2026-03-16T12:00:00Z')).toBe('March 16, 2026')
  })

  it('resolves display name and issue/expiry dates', () => {
    const document = {
      document_type: 'PASSPORT',
      issued_at: '2026-01-01T00:00:00Z',
      expires_at: '2027-01-01T00:00:00Z',
      metadata: { credential_display_name: 'Digital Passport' },
    }

    expect(getMyDocumentDisplayName(document)).toBe('Digital Passport')
    expect(getMyDocumentIssueDate(document)).toBe('2026-01-01T00:00:00Z')
    expect(getMyDocumentExpiryDate(document)).toBe('2027-01-01T00:00:00Z')
  })

  it('derives expired, expiring, and valid statuses', () => {
    const now = new Date('2026-03-16T00:00:00Z')

    expect(isMyDocumentExpired('2026-03-01T00:00:00Z', now)).toBe(true)
    expect(isMyDocumentExpiringSoon('2026-06-01T00:00:00Z', now)).toBe(true)

    expect(getMyDocumentStatus({ expires_at: '2026-03-01T00:00:00Z' }, now)).toEqual({
      key: 'expired',
      label: 'Expired',
      color: 'error',
    })

    expect(getMyDocumentStatus({ expires_at: '2026-06-01T00:00:00Z' }, now)).toEqual({
      key: 'expiring',
      label: 'Expiring Soon',
      color: 'warning',
    })

    expect(getMyDocumentStatus({ expires_at: '2027-03-16T00:00:00Z' }, now)).toEqual({
      key: 'valid',
      label: 'Valid',
      color: 'success',
    })
  })

  it('falls back to user nationality and normalizes loaded credentials', async () => {
    expect(getMyDocumentNationality({}, { nationality: 'USA' } as any)).toBe('USA')
    expect(getMyDocumentNationality({}, null)).toBe('N/A')

    await expect(loadMyDocuments({
      getMyCredentials: vi.fn().mockResolvedValue({
        items: [{ id: 'cred-1' }],
      }),
    })).resolves.toEqual([{ id: 'cred-1' }])
  })
})
