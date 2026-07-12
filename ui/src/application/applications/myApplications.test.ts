import { describe, expect, it, vi } from 'vitest'

import {
  MY_APPLICATION_STATUS_COLORS,
  MY_APPLICATION_STATUS_LABELS,
  buildMyApplicationEditNavigation,
  canAddMyApplicationToWallet,
  canEditMyApplication,
  formatMyApplicationDate,
  formatMyApplicationId,
  getMyApplicationStatusPresentation,
  loadMyApplications,
  normalizeMyApplicationStatus,
} from './myApplications'

describe('myApplications helpers', () => {
  it('normalizes and presents application statuses', () => {
    expect(normalizeMyApplicationStatus('PENDING_APPROVAL')).toBe('pending_approval')
    expect(getMyApplicationStatusPresentation('PENDING_APPROVAL')).toEqual({
      status: 'pending_approval',
      label: MY_APPLICATION_STATUS_LABELS.pending_approval,
      color: MY_APPLICATION_STATUS_COLORS.pending_approval,
    })
  })

  it('formats dates and ids safely', () => {
    expect(formatMyApplicationDate(null)).toBe('N/A')
    expect(formatMyApplicationId('123456789')).toBe('12345678...')
    expect(formatMyApplicationId('short')).toBe('short')
  })

  it('derives edit and wallet action availability', () => {
    expect(canEditMyApplication({ status: 'needs_revision' })).toBe(true)
    expect(canEditMyApplication({ status: 'submitted' })).toBe(false)
    expect(canAddMyApplicationToWallet({ status: 'approved' })).toBe(true)
    expect(canAddMyApplicationToWallet({ status: 'offered' })).toBe(true)
    expect(canAddMyApplicationToWallet({ status: 'issued' })).toBe(false)
    expect(canAddMyApplicationToWallet({ status: 'under_review' })).toBe(false)
  })

  it('builds edit navigation state', () => {
    expect(buildMyApplicationEditNavigation({
      id: 'app-1',
      credential_template_id: 'cfg-1',
      status: 'needs_revision',
    })).toEqual({
      path: '/application/cfg-1',
      state: {
        applicationId: 'app-1',
        revisionData: {
          id: 'app-1',
          credential_template_id: 'cfg-1',
          status: 'needs_revision',
        },
      },
    })
  })

  it('loads normalized applications from the injected service', async () => {
    const listApplications = vi.fn().mockResolvedValue({
      applications: [{ id: 'app-1' }],
      total: 1,
    })

    await expect(loadMyApplications({ listApplications })).resolves.toEqual({
      applications: [{ id: 'app-1' }],
      total: 1,
    })

    expect(listApplications).toHaveBeenCalledWith({ limit: 50 })
  })
})
