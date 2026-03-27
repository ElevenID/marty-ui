/**
 * useWizard Hook
 * 
 * Reusable wizard state management following the PolicyWizard pattern.
 * Provides step navigation, validation, data management, and submission handling.
 * 
 * @example
 * const wizard = useWizard({
 *   steps: ['Basics', 'Details', 'Review'],
 *   initialData: { name: '', description: '' },
 *   onSubmit: async (data) => { ... },
 *   validateStep: (stepIndex, data) => boolean,
 * });
 */

import { useState, useCallback } from 'react';

/**
 * @typedef {Object} WizardConfig
 * @property {string[]} steps - Array of step labels
 * @property {Object} initialData - Initial form data
 * @property {Function} onSubmit - Async submission handler
 * @property {Function} validateStep - Step validation function (stepIndex, data) => boolean
 * @property {Function} onComplete - Optional callback on successful submission
 * @property {Function} onCancel - Optional callback on cancel
 */

/**
 * @param {WizardConfig} config
 */
export function useWizard({
  steps,
  initialData = {},
  onSubmit,
  validateStep,
  onComplete,
  onCancel,
}) {
  const [activeStep, setActiveStep] = useState(0);
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  /**
   * Update wizard data
   */
  const updateData = useCallback((updates) => {
    setData((prev) => ({ ...prev, ...updates }));
  }, []);

  /**
   * Set data for a specific step (useful for complex nested data)
   */
  const setStepData = useCallback((stepKey, value) => {
    setData((prev) => ({ ...prev, [stepKey]: value }));
  }, []);

  /**
   * Check if current step is valid
   */
  const isStepValid = useCallback(() => {
    if (!validateStep) return true;
    return validateStep(activeStep, data);
  }, [activeStep, data, validateStep]);

  /**
   * Navigate to next step
   */
  const goNext = useCallback(() => {
    if (!isStepValid()) return;
    setError(null);
    setActiveStep((prev) => Math.min(prev + 1, steps.length - 1));
  }, [isStepValid, steps.length]);

  /**
   * Navigate to previous step
   */
  const goBack = useCallback(() => {
    setError(null);
    setActiveStep((prev) => Math.max(prev - 1, 0));
  }, []);

  /**
   * Jump to a specific step (for edit from review)
   */
  const goToStep = useCallback((stepIndex) => {
    if (stepIndex >= 0 && stepIndex < steps.length) {
      setError(null);
      setActiveStep(stepIndex);
    }
  }, [steps.length]);

  /**
   * Submit the wizard
   */
  const submit = useCallback(async () => {
    if (!onSubmit) {
      console.error('No onSubmit handler provided to useWizard');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await onSubmit(data);
      setSuccess(true);

      if (onComplete) {
        // Delay to show success message
        setTimeout(() => {
          onComplete(result);
        }, 1500);
      }

      return result;
    } catch (err) {
      console.error('Wizard submission failed:', err);
      setError(err.message || 'Submission failed');
      return null;
    } finally {
      setLoading(false);
    }
  }, [data, onSubmit, onComplete]);

  /**
   * Cancel the wizard
   */
  const cancel = useCallback(() => {
    if (onCancel) {
      onCancel();
    }
  }, [onCancel]);

  /**
   * Reset wizard to initial state
   */
  const reset = useCallback(() => {
    setActiveStep(0);
    setData(initialData);
    setLoading(false);
    setError(null);
    setSuccess(false);
  }, [initialData]);

  return {
    // State
    activeStep,
    data,
    loading,
    error,
    success,
    steps,
    
    // Computed
    isFirstStep: activeStep === 0,
    isLastStep: activeStep === steps.length - 1,
    currentStepLabel: steps[activeStep],
    
    // Validation
    isStepValid,
    
    // Navigation
    goNext,
    goBack,
    goToStep,
    
    // Data management
    updateData,
    setStepData,
    
    // Actions
    submit,
    cancel,
    reset,
    
    // Error handling
    setError,
    clearError: () => setError(null),
  };
}
