/**
 * Payment Context
 *
 * Provides payment functionality with mockable Square Web Payments SDK.
 * Supports vendor subscription payments and applicant processing fee payments.
 *
 * Configuration:
 * - VITE_USE_MOCK_PAYMENTS=true: Uses mock payment provider (dev/test)
 * - VITE_SQUARE_APP_ID: Square application ID (production)
 * - VITE_SQUARE_LOCATION_ID: Square location ID (production)
 */

import React, { createContext, useContext, useState, useCallback, useMemo, useEffect } from 'react';

// Processing fee limits (defined by business rules)
const MIN_PROCESSING_FEE = 0; // $0 minimum
const MAX_PROCESSING_FEE = 50; // $50 maximum

/**
 * @typedef {Object} PaymentResult
 * @property {boolean} success - Whether payment was successful
 * @property {string|null} paymentId - Payment/transaction ID from provider
 * @property {string|null} error - Error message if failed
 * @property {Object|null} metadata - Additional payment metadata
 */

/**
 * @typedef {Object} PaymentContextValue
 * @property {boolean} isReady - Whether payment provider is initialized
 * @property {boolean} isMockMode - Whether using mock payments
 * @property {boolean} isProcessing - Whether a payment is in progress
 * @property {function} initializePayment - Initialize payment for an amount
 * @property {function} processPayment - Process a payment with card details
 * @property {function} validateProcessingFee - Validate a processing fee amount
 * @property {number} minProcessingFee - Minimum allowed processing fee
 * @property {number} maxProcessingFee - Maximum allowed processing fee
 */

const defaultContextValue = {
  isReady: false,
  isMockMode: true,
  isProcessing: false,
  initializePayment: async () => ({ success: false, error: 'Not initialized' }),
  processPayment: async () => ({ success: false, error: 'Not initialized' }),
  validateProcessingFee: () => ({ valid: false, error: 'Not initialized' }),
  minProcessingFee: MIN_PROCESSING_FEE,
  maxProcessingFee: MAX_PROCESSING_FEE,
};

export const PaymentContext = createContext(defaultContextValue);

/**
 * Mock Payment Provider
 * Simulates Square payment processing for development/testing.
 */
class MockPaymentProvider {
  constructor() {
    this.initialized = true;
  }

  async createPayment(amount, currency, sourceId, metadata = {}) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 800 + Math.random() * 400));

    // Simulate occasional failures for testing (5% failure rate)
    if (Math.random() < 0.05) {
      return {
        success: false,
        paymentId: null,
        error: 'MOCK_PAYMENT_DECLINED',
        metadata: { reason: 'Card declined (simulated)' },
      };
    }

    // Generate mock payment ID
    const paymentId = `mock_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    return {
      success: true,
      paymentId,
      error: null,
      metadata: {
        ...metadata,
        amount,
        currency,
        provider: 'mock',
        processedAt: new Date().toISOString(),
      },
    };
  }

  async tokenizeCard(cardData) {
    // Simulate tokenization
    await new Promise((resolve) => setTimeout(resolve, 300));
    return {
      success: true,
      token: `mock_token_${Date.now()}`,
      error: null,
    };
  }
}

/**
 * Square Payment Provider
 * Uses Square Web Payments SDK for real payment processing.
 */
class SquarePaymentProvider {
  constructor(appId, locationId) {
    this.appId = appId;
    this.locationId = locationId;
    this.payments = null;
    this.card = null;
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return true;

    try {
      // Load Square Web Payments SDK
      if (!window.Square) {
        throw new Error('Square SDK not loaded. Add script to index.html');
      }

      this.payments = window.Square.payments(this.appId, this.locationId);
      this.card = await this.payments.card();
      this.initialized = true;
      return true;
    } catch (error) {
      console.error('Square initialization failed:', error);
      return false;
    }
  }

  async attachCard(containerId) {
    if (!this.card) {
      throw new Error('Card not initialized');
    }
    await this.card.attach(`#${containerId}`);
  }

  async tokenizeCard() {
    if (!this.card) {
      return { success: false, token: null, error: 'Card not initialized' };
    }

    try {
      const result = await this.card.tokenize();
      if (result.status === 'OK') {
        return { success: true, token: result.token, error: null };
      }
      return {
        success: false,
        token: null,
        error: result.errors?.[0]?.message || 'Tokenization failed',
      };
    } catch (error) {
      return { success: false, token: null, error: error.message };
    }
  }

  async createPayment(amount, currency, sourceId, metadata = {}) {
    // This would typically call your backend API which then calls Square
    try {
      const response = await fetch('/api/payments/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount_cents: Math.round(amount * 100),
          currency,
          source_id: sourceId,
          ...metadata,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          paymentId: null,
          error: data.error || 'Payment failed',
          metadata: null,
        };
      }

      return {
        success: true,
        paymentId: data.payment_id,
        error: null,
        metadata: data,
      };
    } catch (error) {
      return {
        success: false,
        paymentId: null,
        error: error.message,
        metadata: null,
      };
    }
  }
}

/**
 * Payment Provider Component
 *
 * Provides payment context with automatic mock/real switching.
 */
export function PaymentProvider({ children }) {
  const [isReady, setIsReady] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [provider, setProvider] = useState(null);

  // Determine if we should use mock mode
  const isMockMode = useMemo(() => {
    const envMock = process.env.REACT_APP_USE_MOCK_PAYMENTS;
    // Default to mock in development, or if explicitly enabled
    return envMock === 'true' || envMock === true || process.env.NODE_ENV === 'development';
  }, []);

  // Initialize payment provider
  useEffect(() => {
    const initProvider = async () => {
      if (isMockMode) {
        setProvider(new MockPaymentProvider());
        setIsReady(true);
        console.log('[PaymentContext] Using mock payment provider');
      } else {
        const appId = process.env.REACT_APP_SQUARE_APP_ID;
        const locationId = process.env.REACT_APP_SQUARE_LOCATION_ID;

        if (!appId || !locationId) {
          console.error('[PaymentContext] Square credentials not configured, falling back to mock');
          setProvider(new MockPaymentProvider());
          setIsReady(true);
          return;
        }

        const squareProvider = new SquarePaymentProvider(appId, locationId);
        const initialized = await squareProvider.initialize();

        if (initialized) {
          setProvider(squareProvider);
          setIsReady(true);
          console.log('[PaymentContext] Using Square payment provider');
        } else {
          console.error('[PaymentContext] Square init failed, falling back to mock');
          setProvider(new MockPaymentProvider());
          setIsReady(true);
        }
      }
    };

    initProvider();
  }, [isMockMode]);

  /**
   * Validate a processing fee amount.
   * @param {number} amount - Fee amount in dollars
   * @returns {{ valid: boolean, error: string|null }}
   */
  const validateProcessingFee = useCallback((amount) => {
    if (typeof amount !== 'number' || isNaN(amount)) {
      return { valid: false, error: 'Amount must be a number' };
    }
    if (amount < MIN_PROCESSING_FEE) {
      return { valid: false, error: `Minimum fee is $${MIN_PROCESSING_FEE}` };
    }
    if (amount > MAX_PROCESSING_FEE) {
      return { valid: false, error: `Maximum fee is $${MAX_PROCESSING_FEE}` };
    }
    return { valid: true, error: null };
  }, []);

  /**
   * Initialize a payment (attach card form for Square, no-op for mock).
   * @param {string} containerId - DOM element ID for card form (Square only)
   * @returns {Promise<{ success: boolean, error: string|null }>}
   */
  const initializePayment = useCallback(
    async (containerId) => {
      if (!provider) {
        return { success: false, error: 'Provider not ready' };
      }

      if (isMockMode) {
        // Mock mode doesn't need card attachment
        return { success: true, error: null };
      }

      try {
        await provider.attachCard(containerId);
        return { success: true, error: null };
      } catch (error) {
        return { success: false, error: error.message };
      }
    },
    [provider, isMockMode]
  );

  /**
   * Process a payment.
   * @param {number} amount - Amount in dollars
   * @param {string} currency - Currency code (default: USD)
   * @param {Object} metadata - Additional payment metadata
   * @returns {Promise<PaymentResult>}
   */
  const processPayment = useCallback(
    async (amount, currency = 'USD', metadata = {}) => {
      if (!provider) {
        return { success: false, paymentId: null, error: 'Provider not ready', metadata: null };
      }

      if (isProcessing) {
        return { success: false, paymentId: null, error: 'Payment already in progress', metadata: null };
      }

      setIsProcessing(true);

      try {
        let sourceId = 'mock_source';

        if (!isMockMode) {
          // Tokenize card for Square
          const tokenResult = await provider.tokenizeCard();
          if (!tokenResult.success) {
            return { success: false, paymentId: null, error: tokenResult.error, metadata: null };
          }
          sourceId = tokenResult.token;
        }

        const result = await provider.createPayment(amount, currency, sourceId, metadata);
        return result;
      } catch (error) {
        return { success: false, paymentId: null, error: error.message, metadata: null };
      } finally {
        setIsProcessing(false);
      }
    },
    [provider, isMockMode, isProcessing]
  );

  const contextValue = useMemo(
    () => ({
      isReady,
      isMockMode,
      isProcessing,
      initializePayment,
      processPayment,
      validateProcessingFee,
      minProcessingFee: MIN_PROCESSING_FEE,
      maxProcessingFee: MAX_PROCESSING_FEE,
    }),
    [isReady, isMockMode, isProcessing, initializePayment, processPayment, validateProcessingFee]
  );

  return <PaymentContext.Provider value={contextValue}>{children}</PaymentContext.Provider>;
}

/**
 * Hook to access payment context.
 * @returns {PaymentContextValue}
 */
export function usePayment() {
  const context = useContext(PaymentContext);
  if (!context) {
    throw new Error('usePayment must be used within a PaymentProvider');
  }
  return context;
}

export default PaymentContext;
