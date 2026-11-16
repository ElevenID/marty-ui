/**
 * SSE (Server-Sent Events) Service
 * 
 * Wraps EventSource API for real-time notifications from backend.
 * Integrates with existing SSE infrastructure (/api/events/*) for
 * digital identity events: credentials issued, applications approved,
 * credentials revoked, verification completed.
 */

/**
 * Event type constants for digital identity flows
 */
export const EVENT_TYPES = {
  // Flow events
  FLOW_EXECUTION_STARTED: 'flow.execution.started',
  FLOW_EXECUTION_COMPLETED: 'flow.execution.completed',
  FLOW_EXECUTION_FAILED: 'flow.execution.failed',
  
  // Application events
  APPLICATION_SUBMITTED: 'application.submitted',
  APPLICATION_APPROVED: 'application.approved',
  APPLICATION_REJECTED: 'application.rejected',
  
  // Credential lifecycle events
  CREDENTIAL_ISSUED: 'credential.issued',
  CREDENTIAL_REVOKED: 'credential.revoked',
  CREDENTIAL_SUSPENDED: 'credential.suspended',
  CREDENTIAL_REACTIVATED: 'credential.reactivated',
  
  // Revocation batch events
  REVOCATION_BATCH_QUEUED: 'revocation_batch.queued',
  REVOCATION_BATCH_PROCESSING: 'revocation_batch.processing',
  REVOCATION_BATCH_COMPLETED: 'revocation_batch.completed',
  REVOCATION_BATCH_FAILED: 'revocation_batch.failed',
  
  // Verification events
  VERIFICATION_COMPLETED: 'verification.completed',
  VERIFICATION_FAILED: 'verification.failed',
};

function logSseDebug(...args) {
  if (import.meta.env.DEV && import.meta.env.MODE !== 'test') {
    console.debug(...args);
  }
}

function logSseWarning(...args) {
  if (import.meta.env.DEV && import.meta.env.MODE !== 'test') {
    console.warn(...args);
  }
}

function logSseError(...args) {
  if (import.meta.env.DEV && import.meta.env.MODE !== 'test') {
    console.error(...args);
  }
}

/**
 * SSE Service for managing real-time event subscriptions
 */
class SSEService {
  constructor() {
    this.eventSource = null;
    this.listeners = new Map(); // event_type -> Set of callbacks
    this.isConnected = false;
    this.connectionRequested = false;
    this.connectionGeneration = 0;
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000; // Start with 1 second
  }

  /**
   * Connect to SSE endpoint with optional organization/user filtering
   * @param {Object} options - Connection options
   * @param {string} options.organizationId - Optional organization ID filter
   * @param {string} options.userId - Optional user ID filter
   * @param {Array<string>} options.subscriptions - Optional event type filters
   */
  connect(options = {}) {
    if (this.connectionRequested) {
      logSseWarning('SSE already connected. Disconnect first to reconnect.');
      return;
    }

    // Build SSE URL with query parameters
    const params = new URLSearchParams();
    if (options.organizationId) {
      params.append('organization_id', options.organizationId);
    }
    if (options.userId) {
      params.append('user_id', options.userId);
    }
    if (options.subscriptions && options.subscriptions.length > 0) {
      params.append('subscriptions', options.subscriptions.join(','));
    }

    const sseUrl = `/v1/notifications/events/push${params.toString() ? '?' + params.toString() : ''}`;

    this.connectionRequested = true;
    this.reconnectAttempts = 0;
    const generation = ++this.connectionGeneration;
    try {
      this._openConnection(sseUrl, generation);
    } catch (error) {
      this.disconnect();
      logSseError('Failed to create SSE connection:', error);
      throw error;
    }
  }

  _openConnection(sseUrl, generation) {
    const source = new EventSource(sseUrl);
    this.eventSource = source;
    let openedAt = null;
    const isCurrent = () => this.connectionRequested
      && this.connectionGeneration === generation && this.eventSource === source;

    source.onopen = () => {
      if (!isCurrent()) return;
      openedAt = Date.now();
      logSseDebug('SSE connection established');
      this.isConnected = true;
      this._emit('connection', { status: 'connected' });
    };

    source.onerror = (error) => {
      if (!isCurrent()) return;
      // HTTP 200 can precede an upstream stream failure. Only a stable open
      // connection resets the retry budget, not a brief open/error cycle.
      if (openedAt !== null && Date.now() - openedAt >= 30000) {
        this.reconnectAttempts = 0;
      }
      source.close(); // Stop EventSource's own retry loop before our backoff.
      this.eventSource = null;
      this.isConnected = false;
      this._handleConnectionError(error, sseUrl, generation);
    };

    Object.values(EVENT_TYPES).forEach((eventType) => {
      source.addEventListener(eventType, (event) => {
        if (!isCurrent()) return;
        try {
          const data = JSON.parse(event.data);
          logSseDebug(`SSE event received: ${eventType}`, data);
          this._emit(eventType, data);
        } catch (error) {
          logSseError(`Failed to parse SSE event data for ${eventType}:`, error);
        }
      });
    });

    source.onmessage = (event) => {
      if (!isCurrent()) return;
      try {
        const data = JSON.parse(event.data);
        logSseDebug('SSE generic message received:', data);
        this._emit('message', data);
        if (data.type && isCurrent()) {
          this._emit(data.type, data);
        }
      } catch (error) {
        logSseError('Failed to parse SSE message:', error);
      }
    };
  }

  _handleConnectionError(error, sseUrl, generation) {
    if (!this.connectionRequested || this.connectionGeneration !== generation) return;
    logSseWarning('SSE connection error:', error);
    this._emit('error', { error });
    // A listener may have disconnected or switched the account/organization.
    if (!this.connectionRequested || this.connectionGeneration !== generation) return;

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logSseWarning('Max reconnection attempts reached. Manual reconnection required.');
      this.disconnect();
      return;
    }
    this.reconnectAttempts += 1;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    logSseDebug(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    const timer = setTimeout(() => {
      if (!this.connectionRequested || this.connectionGeneration !== generation || this.reconnectTimer !== timer) return;
      this.reconnectTimer = null;
      try {
        this._openConnection(sseUrl, generation);
      } catch (nextError) {
        this._handleConnectionError(nextError, sseUrl, generation);
      }
    }, delay);
    this.reconnectTimer = timer;
  }

  /**
   * Disconnect from SSE endpoint
   */
  disconnect() {
    const hadConnection = this.connectionRequested;
    this.connectionRequested = false;
    this.connectionGeneration += 1;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.isConnected = false;
    this.reconnectAttempts = 0;
    if (hadConnection) {
      logSseDebug('SSE connection closed');
      this._emit('connection', { status: 'disconnected' });
    }
  }

  /**
   * Subscribe to a specific event type
   * @param {string} eventType - Event type to listen for
   * @param {Function} callback - Callback function(data)
   * @returns {Function} Unsubscribe function
   */
  on(eventType, callback) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    
    this.listeners.get(eventType).add(callback);

    // Return unsubscribe function
    return () => {
      this.off(eventType, callback);
    };
  }

  /**
   * Unsubscribe from a specific event type
   * @param {string} eventType - Event type
   * @param {Function} callback - Callback to remove
   */
  off(eventType, callback) {
    if (this.listeners.has(eventType)) {
      this.listeners.get(eventType).delete(callback);
      
      // Clean up empty listener sets
      if (this.listeners.get(eventType).size === 0) {
        this.listeners.delete(eventType);
      }
    }
  }

  /**
   * Internal method to emit events to listeners
   * @private
   */
  _emit(eventType, data) {
    if (this.listeners.has(eventType)) {
      this.listeners.get(eventType).forEach((callback) => {
        try {
          callback(data);
        } catch (error) {
          logSseError(`Error in SSE event listener for ${eventType}:`, error);
        }
      });
    }
  }

  /**
   * Check if SSE is connected
   * @returns {boolean}
   */
  isActive() {
    return this.isConnected && this.eventSource !== null;
  }
}

// Export singleton instance
export const sseService = new SSEService();

export default sseService;
