/**
 * Unit Tests for useWizard Hook
 * 
 * Tests wizard state management, step navigation, validation, data management,
 * and submission flow.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useWizard } from '../useWizard'

describe('useWizard', () => {
  const mockSteps = ['Basics', 'Details', 'Review']
  const mockInitialData = { name: '', description: '' }
  const mockOnSubmit = vi.fn()
  const mockValidateStep = vi.fn()
  const mockOnComplete = vi.fn()
  const mockOnCancel = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('initialization', () => {
    it('should initialize with default state', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          validateStep: mockValidateStep,
        })
      )

      expect(result.current.activeStep).toBe(0)
      expect(result.current.data).toEqual(mockInitialData)
      expect(result.current.loading).toBe(false)
      expect(result.current.error).toBeNull()
      expect(result.current.success).toBe(false)
      expect(result.current.steps).toEqual(mockSteps)
    })

    it('should compute derived state correctly', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      expect(result.current.isFirstStep).toBe(true)
      expect(result.current.isLastStep).toBe(false)
      expect(result.current.currentStepLabel).toBe('Basics')
    })
  })

  describe('step navigation', () => {
    it('should navigate to next step when valid', () => {
      mockValidateStep.mockReturnValue(true)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          validateStep: mockValidateStep,
        })
      )

      act(() => {
        result.current.goNext()
      })

      expect(result.current.activeStep).toBe(1)
      expect(result.current.currentStepLabel).toBe('Details')
      expect(mockValidateStep).toHaveBeenCalledWith(0, mockInitialData)
    })

    it('should not navigate to next step when invalid', () => {
      mockValidateStep.mockReturnValue(false)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          validateStep: mockValidateStep,
        })
      )

      act(() => {
        result.current.goNext()
      })

      expect(result.current.activeStep).toBe(0)
      expect(mockValidateStep).toHaveBeenCalled()
    })

    it('should navigate to previous step', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      // Navigate to step 2
      act(() => {
        result.current.goToStep(2)
      })
      expect(result.current.activeStep).toBe(2)

      // Go back
      act(() => {
        result.current.goBack()
      })
      expect(result.current.activeStep).toBe(1)
    })

    it('should not go below step 0', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.goBack()
      })

      expect(result.current.activeStep).toBe(0)
    })

    it('should not go beyond last step', () => {
      mockValidateStep.mockReturnValue(true)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          validateStep: mockValidateStep,
        })
      )

      // Navigate to last step
      act(() => {
        result.current.goToStep(2)
      })
      expect(result.current.activeStep).toBe(2)

      // Try to go next
      act(() => {
        result.current.goNext()
      })
      expect(result.current.activeStep).toBe(2)
    })

    it('should jump to specific step', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.goToStep(2)
      })

      expect(result.current.activeStep).toBe(2)
      expect(result.current.currentStepLabel).toBe('Review')
      expect(result.current.isLastStep).toBe(true)
    })

    it('should not jump to invalid step index', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.goToStep(99)
      })

      expect(result.current.activeStep).toBe(0)
    })

    it('should clear error when navigating', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.setError('Test error')
      })
      expect(result.current.error).toBe('Test error')

      act(() => {
        result.current.goNext()
      })
      expect(result.current.error).toBeNull()
    })
  })

  describe('data management', () => {
    it('should update data via updateData', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.updateData({ name: 'Test Name' })
      })

      expect(result.current.data).toEqual({
        name: 'Test Name',
        description: '',
      })
    })

    it('should merge updates with existing data', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.updateData({ name: 'Name' })
      })
      act(() => {
        result.current.updateData({ description: 'Description' })
      })

      expect(result.current.data).toEqual({
        name: 'Name',
        description: 'Description',
      })
    })

    it('should set step data via setStepData', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.setStepData('basics', { name: 'Test', email: 'test@example.com' })
      })

      expect(result.current.data.basics).toEqual({
        name: 'Test',
        email: 'test@example.com',
      })
    })
  })

  describe('validation', () => {
    it('should call validateStep with current step and data', () => {
      mockValidateStep.mockReturnValue(true)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          validateStep: mockValidateStep,
        })
      )

      act(() => {
        result.current.updateData({ name: 'Test' })
      })

      const isValid = result.current.isStepValid()

      expect(isValid).toBe(true)
      expect(mockValidateStep).toHaveBeenCalledWith(0, {
        name: 'Test',
        description: '',
      })
    })

    it('should return true when no validator provided', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      const isValid = result.current.isStepValid()

      expect(isValid).toBe(true)
    })
  })

  describe('submission', () => {
    it('should submit successfully', async () => {
      const mockResult = { id: 1, name: 'Created' }
      mockOnSubmit.mockResolvedValue(mockResult)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          onComplete: mockOnComplete,
        })
      )

      act(() => {
        result.current.updateData({ name: 'Test', description: 'Description' })
      })

      let submitResult
      await act(async () => {
        submitResult = await result.current.submit()
      })

      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: 'Test',
        description: 'Description',
      })
      expect(submitResult).toEqual(mockResult)
      expect(result.current.success).toBe(true)
      expect(result.current.loading).toBe(false)
      expect(result.current.error).toBeNull()

      // Wait for onComplete to be called after delay
      await waitFor(() => {
        expect(mockOnComplete).toHaveBeenCalledWith(mockResult)
      }, { timeout: 2000 })
    })

    it('should handle submission error', async () => {
      const mockError = new Error('Submission failed')
      mockOnSubmit.mockRejectedValue(mockError)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      await act(async () => {
        try {
          await result.current.submit()
        } catch (err) {
          // Expected to throw
        }
      })

      expect(result.current.error).toBe('Submission failed')
      expect(result.current.success).toBe(false)
      expect(result.current.loading).toBe(false)
    })

    it('should surface unknown operation status with the idempotency key', async () => {
      const mockError = Object.assign(new Error('Failed to fetch'), {
        operationStatusUnknown: true,
        idempotencyKey: 'templates:create:123',
      })
      mockOnSubmit.mockRejectedValue(mockError)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      await act(async () => {
        await result.current.submit()
      })

      expect(result.current.error).toContain('Operation status unknown')
      expect(result.current.error).toContain('templates:create:123')
      expect(result.current.error).toContain('Refresh the page')
    })

    it('should set loading state during submission', async () => {
      let resolveSubmit: (value: any) => void
      const submitPromise = new Promise((resolve) => {
        resolveSubmit = resolve
      })
      mockOnSubmit.mockReturnValue(submitPromise)

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.submit()
      })

      // Should be loading immediately
      expect(result.current.loading).toBe(true)

      // Resolve submission
      await act(async () => {
        resolveSubmit!({ id: 1 })
        await submitPromise
      })

      expect(result.current.loading).toBe(false)
    })

    it('should clear error before submission', async () => {
      mockOnSubmit.mockResolvedValue({ id: 1 })

      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.setError('Previous error')
      })
      expect(result.current.error).toBe('Previous error')

      await act(async () => {
        await result.current.submit()
      })

      expect(result.current.error).toBeNull()
    })
  })

  describe('cancel', () => {
    it('should call onCancel handler', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
          onCancel: mockOnCancel,
        })
      )

      act(() => {
        result.current.cancel()
      })

      expect(mockOnCancel).toHaveBeenCalled()
    })

    it('should not error when no onCancel provided', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      expect(() => {
        act(() => {
          result.current.cancel()
        })
      }).not.toThrow()
    })
  })

  describe('reset', () => {
    it('should reset wizard to initial state', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      // Make changes
      act(() => {
        result.current.goToStep(2)
        result.current.updateData({ name: 'Test', description: 'Description' })
        result.current.setError('Test error')
      })

      expect(result.current.activeStep).toBe(2)
      expect(result.current.data.name).toBe('Test')
      expect(result.current.error).toBe('Test error')

      // Reset
      act(() => {
        result.current.reset()
      })

      expect(result.current.activeStep).toBe(0)
      expect(result.current.data).toEqual(mockInitialData)
      expect(result.current.loading).toBe(false)
      expect(result.current.error).toBeNull()
      expect(result.current.success).toBe(false)
    })
  })

  describe('error handling', () => {
    it('should set and clear error', () => {
      const { result } = renderHook(() =>
        useWizard({
          steps: mockSteps,
          initialData: mockInitialData,
          onSubmit: mockOnSubmit,
        })
      )

      act(() => {
        result.current.setError('Test error')
      })
      expect(result.current.error).toBe('Test error')

      act(() => {
        result.current.clearError()
      })
      expect(result.current.error).toBeNull()
    })
  })
})
