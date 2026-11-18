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

import { useState, useCallback, useLayoutEffect, useRef } from 'react';
import { operationStatusUnknownMessage } from '../services/idempotency';

const SHOULD_LOG_WIZARD_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function logWizardError(...args) {
  if (SHOULD_LOG_WIZARD_DIAGNOSTICS) {
    console.error(...args);
  }
}

function wizardErrorMessage(error) {
  if (error?.operationStatusUnknown) {
    return operationStatusUnknownMessage(error, 'Operation status unknown');
  }
  const response = error?.response || {};
  const message = response?.error?.user_message
    || response?.error?.message
    || response?.error_description
    || (typeof response?.error === 'string' && response.error !== 'validation_error' ? response.error : null)
    || error?.message
    || 'Submission failed';
  const messageId = response?.message_id || response?.request_id || error?.requestId || null;

  return messageId ? `${message} (Message ID: ${messageId})` : message;
}

/**
 * @typedef {Object} WizardConfig
 * @property {string[]} steps - Array of step labels
 * @property {Object} initialData - Initial form data
 * @property {Function} onSubmit - Async submission handler
 * @property {Function} validateStep - Step validation function (stepIndex, data) => boolean
 * @property {Function} onComplete - Optional callback on successful submission
 * @property {Function} onCancel - Optional callback on cancel
 * @property {string} [scopeKey] - Organization or other submission ownership scope
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
  scopeKey,
}) {
  const [activeStep, setActiveStep] = useState(0);
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [result, setResult] = useState(null);
  const generation = useRef(0);
  const submitting = useRef(false);
  const completionTimer = useRef(null);
  const invalidateSubmission = useCallback(() => {
    generation.current += 1;
    submitting.current = false;
    clearTimeout(completionTimer.current);
    completionTimer.current = null;
  }, []);

  useLayoutEffect(() => {
    invalidateSubmission();
    setResult(null);
    setSuccess(false);
    setLoading(false);
    setError(null);
    return invalidateSubmission;
  }, [scopeKey, invalidateSubmission]);

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
      logWizardError('No onSubmit handler provided to useWizard');
      return;
    }

    if (submitting.current) return null;
    submitting.current = true;
    const submittedGeneration = generation.current;
    clearTimeout(completionTimer.current);

    setLoading(true);
    setError(null);
    setResult(null);
    setSuccess(false);

    try {
      const submittedResult = await onSubmit(data);
      if (generation.current !== submittedGeneration) return null;
      setResult(submittedResult);
      setSuccess(true);

      if (onComplete) {
        // Delay to show success message
        completionTimer.current = setTimeout(() => {
          if (generation.current === submittedGeneration) onComplete(submittedResult);
        }, 1500);
      }

      return submittedResult;
    } catch (err) {
      if (generation.current !== submittedGeneration) return null;
      logWizardError('Wizard submission failed:', err);
      setError(wizardErrorMessage(err));
      return null;
    } finally {
      if (generation.current === submittedGeneration) {
        submitting.current = false;
        setLoading(false);
      }
    }
  }, [data, onSubmit, onComplete]);

  /**
   * Cancel the wizard
   */
  const cancel = useCallback(() => {
    invalidateSubmission();
    setLoading(false);
    if (onCancel) {
      onCancel();
    }
  }, [onCancel, invalidateSubmission]);

  /**
   * Reset wizard to initial state
   */
  const reset = useCallback(() => {
    invalidateSubmission();
    setActiveStep(0);
    setData(initialData);
    setLoading(false);
    setError(null);
    setSuccess(false);
    setResult(null);
  }, [initialData, invalidateSubmission]);

  return {
    // State
    activeStep,
    data,
    loading,
    error,
    success,
    result,
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
